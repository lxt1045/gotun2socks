package main

import (
	"errors"
	"os/exec"
	"strings"
)

// AddRoutes adds routes.
func AddRoutes(proxyIPs []string, gwNew string) error {
	c := exec.Command("ip", "route", "add", "0.0.0.0/1", "via", gwNew)
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("ip", "route", "add", "128.0.0.0/1", "via", gwNew)
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	gw, err := GetDefaultGateway()
	if err != nil {
		return err
	}
	for _, proxyIP := range proxyIPs {
		c = exec.Command("ip", "route", "add", proxyIP, "via", gw)
		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	return nil
}

// DeleteRoutes deletes routes.
func DeleteRoutes(proxyIPs []string, gwNew string) error {
	c := exec.Command("ip", "route", "del", "0.0.0.0/1", "via", gwNew)
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("ip", "route", "del", "128.0.0.0/1", "via", gwNew)
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	gw, err := GetDefaultGateway()
	if err != nil {
		return err
	}
	for _, proxyIP := range proxyIPs {
		c = exec.Command("ip", "route", "del", proxyIP, "via", gw)
		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	return nil
}

// GetDefaultGateway returns default gateway.
func GetDefaultGateway() (string, error) {
	c := exec.Command("sh", "-c", "ip route | grep default | awk '{print $3}'")
	out, err := c.CombinedOutput()
	if err != nil {
		return "", errors.New(string(out) + err.Error())
	}
	return strings.TrimSpace(string(out)), nil
}
