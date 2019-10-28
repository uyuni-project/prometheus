// Copyright 2019 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package uyuni

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kolo/xmlrpc"
	"github.com/pkg/errors"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

const (
	uyuniLabel             = model.MetaLabelPrefix + "uyuni_"
	uyuniLabelEntitlements = uyuniLabel + "entitlements"
)

// DefaultSDConfig is the default Uyuni SD configuration.
var DefaultSDConfig = SDConfig{
	RefreshInterval: model.Duration(1 * time.Minute),
}

// Regular expression to extract port from formula data
var monFormulaRegex = regexp.MustCompile(`--web\.listen-address=\":([0-9]*)\"`)

// SDConfig is the configuration for Uyuni based service discovery.
type SDConfig struct {
	Host            string         `yaml:"host"`
	User            string         `yaml:"username"`
	Pass            string         `yaml:"password"`
	RefreshInterval model.Duration `yaml:"refresh_interval,omitempty"`
}

// Uyuni API Response structures
type clientRef struct {
	Id   int    `xmlrpc:"id"`
	Name string `xmlrpc:"name"`
}

type systemDetail struct {
	Id           int      `xmlrpc:"id"`
	Hostname     string   `xmlrpc:"hostname"`
	Entitlements []string `xmlrpc:"addon_entitlements"`
}

type groupDetail struct {
	Id              int    `xmlrpc:"id"`
	Subscribed      int    `xmlrpc:"subscribed"`
	SystemGroupName string `xmlrpc:"system_group_name"`
}

type networkInfo struct {
	Ip string `xmlrpc:"ip"`
}

type exporterConfig struct {
	Args    string `xmlrpc:"args"`
	Enabled bool   `xmlrpc:"enabled"`
}

type formulaData struct {
	NodeExporter     exporterConfig `xmlrpc:"node_exporter"`
	PostgresExporter exporterConfig `xmlrpc:"postgres_exporter"`
	ApacheExporter   exporterConfig `xmlrpc:"apache_exporter"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *SDConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultSDConfig
	type plain SDConfig
	err := unmarshal((*plain)(c))

	if err != nil {
		return err
	}
	if c.Host == "" {
		return errors.New("Uyuni SD configuration requires a Host")
	}
	if c.User == "" {
		return errors.New("Uyuni SD configuration requires a Username")
	}
	if c.Pass == "" {
		return errors.New("Uyuni SD configuration requires a Password")
	}
	if c.RefreshInterval <= 0 {
		return errors.New("Uyuni SD configuration requires RefreshInterval to be a positive integer")
	}
	return nil
}

// Attempt to login in Uyuni Server and get an auth token
func Login(rpcclient *xmlrpc.Client, user string, pass string) (string, error) {
	var result string
	err := rpcclient.Call("auth.login", []interface{}{user, pass}, &result)
	return result, err
}

// Logout from Uyuni API
func Logout(rpcclient *xmlrpc.Client, token string) error {
	err := rpcclient.Call("auth.logout", token, nil)
	return err
}

// Get system list
func ListSystems(rpcclient *xmlrpc.Client, token string) ([]clientRef, error) {
	var result []clientRef
	err := rpcclient.Call("system.listSystems", token, &result)
	return result, err
}

// Get system details
func GetSystemDetails(rpcclient *xmlrpc.Client, token string, systemId int) (systemDetail, error) {
	var result systemDetail
	err := rpcclient.Call("system.getDetails", []interface{}{token, systemId}, &result)
	return result, err
}

// Get list of groups a system belongs to
func ListSystemGroups(rpcclient *xmlrpc.Client, token string, systemId int) ([]groupDetail, error) {
	var result []groupDetail
	err := rpcclient.Call("system.listGroups", []interface{}{token, systemId}, &result)
	return result, err
}

// List client FQDNs
func GetSystemNetworkInfo(rpcclient *xmlrpc.Client, token string, systemId int) (networkInfo, error) {
	var result networkInfo
	err := rpcclient.Call("system.getNetwork", []interface{}{token, systemId}, &result)
	return result, err
}

// Get formula data for a given system
func GetSystemFormulaData(rpcclient *xmlrpc.Client, token string, systemId int, formulaName string) (formulaData, error) {
	var result formulaData
	err := rpcclient.Call("formula.getSystemFormulaData", []interface{}{token, systemId, formulaName}, &result)
	return result, err
}

// Get formula data for a given group
func GetGroupFormulaData(rpcclient *xmlrpc.Client, token string, groupId int, formulaName string) (formulaData, error) {
	var result formulaData
	err := rpcclient.Call("formula.getGroupFormulaData", []interface{}{token, groupId, formulaName}, &result)
	return result, err
}

// Get exporter port configuration from Formula
func ExtractPortFromFormulaData(args string) (string, error) {
	tokens := monFormulaRegex.FindStringSubmatch(args)
	if len(tokens) < 1 {
		return "", errors.New("Unable to find port in args: " + args)
	}
	return tokens[1], nil
}

// Take a current formula structure and override values if the new config is set
// Used for calculating final formula values when using groups
func GetCombinedFormula(combined formulaData, new formulaData) formulaData {
	if new.NodeExporter.Enabled {
		combined.NodeExporter = new.NodeExporter
	}
	if new.PostgresExporter.Enabled {
		combined.PostgresExporter = new.PostgresExporter
	}
	if new.ApacheExporter.Enabled {
		combined.ApacheExporter = new.ApacheExporter
	}
	return combined
}

// Discovery periodically performs Uyuni API requests. It implements
// the Discoverer interface.
type Discovery struct {
	*refresh.Discovery
	client   *http.Client
	interval time.Duration
	sdConfig *SDConfig
	logger   log.Logger
}

// NewDiscovery returns a new file discovery for the given paths.
func NewDiscovery(conf *SDConfig, logger log.Logger) *Discovery {
	d := &Discovery{
		interval: time.Duration(conf.RefreshInterval),
		sdConfig: conf,
		logger:   logger,
	}
	d.Discovery = refresh.NewDiscovery(
		logger,
		"uyuni",
		time.Duration(conf.RefreshInterval),
		d.refresh,
	)
	return d
}

func (d *Discovery) refresh(ctx context.Context) ([]*targetgroup.Group, error) {

	config := d.sdConfig
	apiUrl := config.Host + "/rpc/api"

	_, err := url.ParseRequestURI(apiUrl)
	if err != nil {
		return nil, errors.Wrap(err, "Uyuni Server URL is not valid")
	}

	rpcclient, _ := xmlrpc.NewClient(apiUrl, nil)
	tg := &targetgroup.Group{
		Source: config.Host,
	}

	// Login into Uyuni API and get auth token
	token, err := Login(rpcclient, config.User, config.Pass)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to login to Uyuni API")
	}

	// Get list of managed clients from Uyuni API
	clientList, err := ListSystems(rpcclient, token)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to get list of systems")
	}

	// Iterate list of clients
	if len(clientList) == 0 {
		fmt.Printf("\tFound 0 systems.\n")
	} else {

		for _, client := range clientList {
			netInfo := networkInfo{}
			formulas := formulaData{}
			groups := []groupDetail{}

			// Get the system details
			details, err := GetSystemDetails(rpcclient, token, client.Id)
			if err != nil {
				level.Error(d.logger).Log("msg", "Unable to get system details", "clientId", client.Id, "err", err)
				continue
			}
			jsonDetails, _ := json.Marshal(details)
			level.Debug(d.logger).Log("msg", "System details", "details", jsonDetails)

			// Check if system is monitoring entitled
			for _, v := range details.Entitlements {
				if v == "monitoring_entitled" { // golang has no native method to check if an element is part of a slice

					// Get network details
					netInfo, err = GetSystemNetworkInfo(rpcclient, token, client.Id)
					if err != nil {
						level.Error(d.logger).Log("msg", "Error getting network information", "clientId", client.Id, "err", err)
						continue
					}

					// Get list of groups this system is assigned to
					groups, err = ListSystemGroups(rpcclient, token, client.Id)
					if err != nil {
						level.Error(d.logger).Log("msg", "Error getting system groups", "clientId", client.Id, "err", err)
						continue
					}
					subGroups := []string{}
					for _, g := range groups {
						// get list of group formulas
						// TODO: Put the resulting data on a map so that we do not have to repeat the call below for every system
						if g.Subscribed == 1 {
							groupFormulas, err := GetGroupFormulaData(rpcclient, token, g.Id, "prometheus-exporters")
							if err != nil {
								level.Error(d.logger).Log("msg", "Error getting group formulas", "groupId", client.Id, "err", err)
								continue
							}
							formulas = GetCombinedFormula(formulas, groupFormulas)
							// replace spaces with dashes on all group names
							subGroups = append(subGroups, strings.ToLower(strings.ReplaceAll(g.SystemGroupName, " ", "-")))
						}
					}

					// Get system formula list
					systemFormulas, err := GetSystemFormulaData(rpcclient, token, client.Id, "prometheus-exporters")
					if err != nil {
						level.Error(d.logger).Log("msg", "Error getting system formulas", "clientId", client.Id, "err", err)
						continue
					}
					formulas = GetCombinedFormula(formulas, systemFormulas)

					// Iterate list of formulas and check for enabled exporters
					for _, f := range []exporterConfig{formulas.NodeExporter, formulas.PostgresExporter, formulas.ApacheExporter} {
						if f.Enabled {
							port, err := ExtractPortFromFormulaData(f.Args)
							if err != nil {
								level.Error(d.logger).Log("msg", "Unable to read exporter port", "clientId", client.Id, "err", err)
								continue
							}
							labels := model.LabelSet{}
							addr := fmt.Sprintf("%s:%s", netInfo.Ip, port)
							labels[model.AddressLabel] = model.LabelValue(addr)
							labels["hostname"] = model.LabelValue(details.Hostname)
							labels["groups"] = model.LabelValue(strings.Join(subGroups, ","))
							tg.Targets = append(tg.Targets, labels)
						}
					}
				}
			}

			// Log debug information
			if netInfo.Ip != "" {
				level.Debug(d.logger).Log("msg", "Found monitored system", "Host", details.Hostname, "Entitlements", fmt.Sprintf("%+v", details.Entitlements), "Network", fmt.Sprintf("%+v", netInfo), "Groups", fmt.Sprintf("%+v", groups), "Formulas", fmt.Sprintf("%+v", formulas))
			}
		}
	}
	Logout(rpcclient, token)
	return []*targetgroup.Group{tg}, nil
}
