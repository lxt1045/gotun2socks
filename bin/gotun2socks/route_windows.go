package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// AddRoutes adds routes.
func AddRoutes(proxyIPs []string, gwNew string) error {
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
	for _, proxyIP := range proxyIPs {
		proxyIP, mask := ParseIP(proxyIP)
		fmt.Printf("route add %s mask %s %s metric 1\n", proxyIP, mask, gw)

		c = exec.Command("route", "add", proxyIP, "mask", mask, gw, "metric", "1")
		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
	}
	return nil
}

func ParseIP(proxyIP string) (ip, mask string) {
	maskS := []string{"255", "255", "255", "255"}
	for nStar := strings.Count(proxyIP, "*"); nStar > 0; nStar-- {
		maskS[len(maskS)-nStar] = "0"
	}
	mask = strings.Join(maskS, ".")
	ip = strings.Replace(proxyIP, "*", "0", -1)
	return
}

// DeleteRoutes deletes routes.
func DeleteRoutes(proxyIPs []string, gwNew string) error {
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

	for _, proxyIP := range proxyIPs {
		proxyIP, mask := ParseIP(proxyIP)
		fmt.Printf("route add %s mask %s %s metric 1\n", proxyIP, mask, gw)
		c = exec.Command("route", "delete", proxyIP, "mask", mask, gw, "metric", "1")
		if out, err := c.CombinedOutput(); err != nil {
			return errors.New(string(out) + err.Error())
		}
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
