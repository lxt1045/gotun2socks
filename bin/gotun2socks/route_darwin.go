package main

import (
	"errors"
	"os/exec"
	"strings"
)

// AddRoutes adds routes.
func AddRoutes(proxyIPs []string, gwNew string) error {
	c := exec.Command("route", "add", "-net", "0.0.0.0", gwNew, "-netmask", "128.0.0.0")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("route", "add", "-net", "128.0.0.0", gwNew, "-netmask", "128.0.0.0")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	gw, err := GetDefaultGateway()
	if err != nil {
		return err
	}
	for _, proxyIP := range proxyIPs {
		c = exec.Command("route", "add", "-host", proxyIP, gw, "-netmask", "255.255.255.255")
		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	return nil
}

// DeleteRoutes deletes routes.
func DeleteRoutes(proxyIPs []string, gwNew string) error {
	c := exec.Command("route", "delete", "-net", "0.0.0.0", gwNew, "-netmask", "128.0.0.0")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("route", "delete", "-net", "128.0.0.0", gwNew, "-netmask", "128.0.0.0")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	gw, err := GetDefaultGateway()
	if err != nil {
		return err
	}
	for _, proxyIP := range proxyIPs {
		c = exec.Command("route", "delete", "-host", proxyIP, gw, "-netmask", "255.255.255.255")
		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	return nil
}

// GetDefaultGateway returns default gateway.
func GetDefaultGateway() (string, error) {
	c := exec.Command("sh", "-c", "route -n get default | grep gateway | awk '{print $2}'")
	out, err := c.CombinedOutput()
	if err != nil {
		return "", errors.New(string(out) + err.Error())
	}
	return strings.TrimSpace(string(out)), nil
}
