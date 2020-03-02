package main

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
)

// AddRoutes adds routes.
func AddRoutes(proxyIP, gwNew string) error {
	c := exec.Command("chcp", "65001")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("route", "add", "0.0.0.0", "mask", "128.0.0.0", gwNew)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("route", "add", "128.0.0.0", "mask", "128.0.0.0", gwNew)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	gw, err := GetDefaultGateway()
	if err != nil {
		return err
	}
	c = exec.Command("route", "add", proxyIP, "mask", "255.255.255.255", gw, "metric", "1")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	return nil
}

// DeleteRoutes deletes routes.
func DeleteRoutes(proxyIP, gwNew string) error {
	c := exec.Command("chcp", "65001")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0", gwNew)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	c = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0", gwNew)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	gw, err := GetDefaultGateway()
	if err != nil {
		return err
	}
	c = exec.Command("route", "delete", proxyIP, "mask", "255.255.255.255", gw, "metric", "1")
	if out, err := c.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}
	return nil
}

// GetDefaultGateway returns default gateway.
func GetDefaultGateway() (string, error) {
	c := exec.Command("chcp", "65001")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := c.CombinedOutput(); err != nil {
		return "", errors.New(string(out) + err.Error())
	}
	c = exec.Command("netsh", "interface", "ip", "show", "address")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := c.CombinedOutput()
	if err != nil {
		return "", errors.New(string(out) + err.Error())
	}
	l := strings.Split(string(out), "\n")
	for _, v := range l {
		if !strings.Contains(v, "Default Gateway") {
			continue
		}
		l1 := strings.Split(v, "Gateway:")
		if len(l1) != 2 {
			continue
		}
		if strings.TrimSpace(l1[1]) == "" {
			continue
		}
		return strings.TrimSpace(l1[1]), nil
	}
	return "", errors.New("Can't find default gateway")
}
