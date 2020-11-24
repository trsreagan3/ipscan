package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"github.com/apparentlymart/go-cidr/cidr"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"	
	"strings"
)

func init(){
	clone()
}

func main() {
	ip_maps, ip_ranges := ListIPs()
	fmt.Println("length ranges:", len(ip_ranges))
	fmt.Println("length ips:", len(ip_maps))
	fmt.Println("first ten ranges:", ip_ranges[:10])
	ip_check := os.Args[1]
	fmt.Println("checking ip:", ip_check)
	check_lists(ip_ranges, ip_maps, ip_check)

}

func clone (){
        cmd := exec.Command("git", "clone", "https://github.com/firehol/blocklist-ipsets")
        err := cmd.Run()
        if err != nil {
		fmt.Println("clone:", err)
        }
}

func GetFiles() (files []string){
        files, err := ListFiles("./blocklist-ipsets", "*.*set")
        if  err  !=  nil {
                fmt.Println(err)
        }   
        return files
}

func ListIPs() (map[uint32]uint32, []ip_range_int){
		
	ip_maps := make(map[uint32]uint32)
	ip_ranges := []ip_range_int{}

        files := GetFiles()
        for _, f := range files {
                file, err := os.Open(f)
		if err != nil {
        		log.Fatal(err)
    		}
    		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
				case string(line[0]) == "#": {
					scanner.Scan()
				}
				case string(line[0]) == ";": {
                                        scanner.Scan()
                                }
				case strings.Contains(line, "/"): {
					ip := CIDRStringToIPNet(line)
					low_ip, high_ip := cidr.AddressRange(ip)
					ip_range := create_range(low_ip,high_ip)
					if ip_range.low == 0 {
						continue
					}
					ip_ranges = append(ip_ranges, ip_range)
				}
				default: {
					ip_val := ipToInt(line)
					ip_maps[ip_val] = ip_val
				}
			}
		}
	}
	return ip_maps, ip_ranges
}


func ListFiles(root, pattern string) ([]string, error) {
    var matches []string
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if info.IsDir() {
            return nil
        }
        if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
            return err
        } else if matched {
            matches = append(matches, path)
        }
        return nil
    })
    if err != nil {
        return nil, err
    }
    return matches, nil
}

func ipToInt (ip string) uint32{
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}

func CIDRStringToIPNet (ip_range string) *net.IPNet{

	_, ipnet, err := net.ParseCIDR(ip_range)
        if err != nil {
            fmt.Println("Error", ip_range, err)
        }
	return ipnet
}

func create_range (low_ip net.IP, high_ip net.IP) ip_range_int{
	rng := ip_range_int{high: ipToInt(high_ip.String()),low:ipToInt(low_ip.String())}
	return rng
}

type ip_range_int struct {
	high uint32
	low uint32
}

func intToIP (ip uint32) (int,error){
	a := make([]byte, 4)
	binary.LittleEndian.PutUint32(a, ip)
	return fmt.Println(a[3],".",a[2],".",a[1],".",a[0])
}

func check_lists(ip_ranges []ip_range_int, ip_maps map[uint32]uint32, ip string) (int,error){
	fmt.Println("checking ip:", ip)
	ip_int := ipToInt(ip)
	fmt.Println(ip, " converted to int is:", ip_int)
	for _,check := range ip_ranges {
		if (ip_int >= check.low && ip_int <= check.high){
			low_ip, err := intToIP(check.low)
			if err != nil {fmt.Println("error converting check.low to subnet")}
			high_ip,  err := intToIP(check.high)
			if err != nil {fmt.Println("error converting check.high to subnet")}
			//fmt.Println("low:" , low_ip, "high:", high_ip)
			return fmt.Println("blocked ip in ranges:", check, "ip:", ip_int)
		} else {
			if ip_maps[ip_int] == ip_int {
				return fmt.Println(ip_int, " ", ip_maps[ip_int], " match")
			}
		}
	}
	return fmt.Println("ip:", ip, "not blocked.", nil)
}
