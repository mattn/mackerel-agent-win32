package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type SYSTEM_INFO struct {
	ProcessorArchitecture     uint16
	PageSize                  uint32
	MinimumApplicationAddress *byte
	MaximumApplicationAddress *byte
	ActiveProcessorMask       *byte
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type MEMORYSTATUSEX struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type PDH_FMT_COUNTERVALUE_DOUBLE struct {
	CStatus     uint32
	DoubleValue float64
}

type PDH_FMT_COUNTERVALUE_ITEM_DOUBLE struct {
	Name     *uint16
	FmtValue PDH_FMT_COUNTERVALUE_DOUBLE
}

const (
	ERROR_SUCCESS      = 0
	DRIVE_FIXED        = 3
	HKEY_LOCAL_MACHINE = 0x80000002
	RRF_RT_REG_SZ      = 0x00000002
	RRF_RT_REG_DWORD   = 0x00000010
	PDH_FMT_DOUBLE     = 0x00000200
	PDH_INVALID_DATA   = 0xc0000bc6
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modpdh      = syscall.NewLazyDLL("pdh.dll")

	procRegGetValue                 = modadvapi32.NewProc("RegGetValueW")
	procGetDiskFreeSpaceEx          = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDriveStrings      = modkernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveType                = modkernel32.NewProc("GetDriveTypeW")
	procQueryDosDevice              = modkernel32.NewProc("QueryDosDeviceW")
	procGetVolumeInformationW       = modkernel32.NewProc("GetVolumeInformationW")
	procGlobalMemoryStatusEx        = modkernel32.NewProc("GlobalMemoryStatusEx")
	procPdhOpenQuery                = modpdh.NewProc("PdhOpenQuery")
	procPdhAddCounter               = modpdh.NewProc("PdhAddCounterW")
	procPdhCollectQueryData         = modpdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterValue = modpdh.NewProc("PdhGetFormattedCounterValue")
	procPdhCloseQuery               = modpdh.NewProc("PdhCloseQuery")
)

func bytePtrToString(p *uint8) string {
	a := (*[10000]uint8)(unsafe.Pointer(p))
	i := 0
	for a[i] != 0 {
		i++
	}
	return string(a[:i])
}

func regGetInt(hKey uint32, subKey string, value string) (uint32, error) {
	var num, numlen uint32
	numlen = 4
	ret, _, err := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_DWORD),
		0,
		uintptr(unsafe.Pointer(&num)),
		uintptr(unsafe.Pointer(&numlen)))
	if ret != ERROR_SUCCESS {
		return 0, err
	}

	return num, nil
}

func regGetString(hKey uint32, subKey string, value string) (string, error) {
	var bufLen uint32
	procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_SZ),
		0,
		0,
		uintptr(unsafe.Pointer(&bufLen)))
	if bufLen == 0 {
		return "", errors.New("Can't get size of registry value")
	}

	buf := make([]uint16, bufLen)
	ret, _, err := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_SZ),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)))
	if ret != ERROR_SUCCESS {
		return "", err
	}

	return syscall.UTF16ToString(buf), nil
}

type info struct {
	counterName string
	counter     syscall.Handle
}

type client struct {
	apibase string
	apikey  string
	hostId  string
	query   syscall.Handle
	infoMap map[string]*info
	Verbose bool
}

func NewClient(apibase, apikey, hostId string, nameMap map[string]string) *client {
	c := new(client)
	r, _, err := procPdhOpenQuery.Call(0, 0, uintptr(unsafe.Pointer(&c.query)))
	if r != 0 {
		log.Fatal(err)
	}
	c.apibase = apibase
	c.apikey = apikey
	c.hostId = hostId

	c.infoMap = make(map[string]*info)
	if err = c.createCounter("loadavg5", `\Processor(_Total)\% Processor Time`); err != nil {
		log.Fatal(err)
	}
	for k, v := range nameMap {
		if err = c.createCounter(k, v); err != nil {
			log.Fatal(err)
		}
	}

	r, _, err = procPdhCollectQueryData.Call(uintptr(c.query))
	if r != 0 {
		log.Fatal(err)
	}
	runtime.SetFinalizer(c, func(c *client) {
		r, _, err := procPdhCloseQuery.Call(uintptr(c.query))
		if r != 0 {
			log.Fatal(err)
		}
	})
	return c
}

func (c *client) createCounter(k, v string) error {
	var counter syscall.Handle
	r, _, err := procPdhAddCounter.Call(
		uintptr(c.query),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(v))),
		0,
		uintptr(unsafe.Pointer(&counter)))
	if r != 0 {
		return err
	}
	c.infoMap[k] = &info{
		counterName: v,
		counter:     counter,
	}
	return nil
}

// getAdapterList return list of adapter information
func getAdapterList() (*syscall.IpAdapterInfo, error) {
	b := make([]byte, 1000)
	l := uint32(len(b))
	a := (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	err := syscall.GetAdaptersInfo(a, &l)
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		b = make([]byte, l)
		a = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
		err = syscall.GetAdaptersInfo(a, &l)
	}
	if err != nil {
		return nil, os.NewSyscallError("GetAdaptersInfo", err)
	}
	return a, nil
}

// postHostInfo post host information
func (c *client) postHostInfo() error {
	info := map[string]interface{}{}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	info["name"] = hostname

	meta := map[string]interface{}{}
	meta["agent-revision"] = ""
	meta["agent-version"] = "0.0"
	meta["block_device"] = map[string]interface{}{}
	kernel32 := syscall.MustLoadDLL("kernel32")
	defer kernel32.Release()
	getSystemInfo := kernel32.MustFindProc("GetSystemInfo")
	var systemInfo SYSTEM_INFO
	getSystemInfo.Call(uintptr(unsafe.Pointer(&systemInfo)))
	var cpuinfos []map[string]interface{}
	for i := uint32(0); i < systemInfo.NumberOfProcessors; i++ {
		processorName, err := regGetString(
			HKEY_LOCAL_MACHINE,
			fmt.Sprintf(`HARDWARE\DESCRIPTION\System\CentralProcessor\%d`, i),
			`ProcessorNameString`)
		if err != nil {
			return err
		}
		processorMHz, err := regGetInt(
			HKEY_LOCAL_MACHINE,
			fmt.Sprintf(`HARDWARE\DESCRIPTION\System\CentralProcessor\%d`, i),
			`~MHz`)
		if err != nil {
			return err
		}
		vendorIdentifier, err := regGetString(
			HKEY_LOCAL_MACHINE,
			fmt.Sprintf(`HARDWARE\DESCRIPTION\System\CentralProcessor\%d`, i),
			`VendorIdentifier`)
		if err != nil {
			return err
		}
		cpuinfos = append(cpuinfos, map[string]interface{}{
			"model_name": processorName,
			"mhz":        processorMHz,
			"model":      systemInfo.ProcessorArchitecture,
			"vendor_id":  vendorIdentifier,
		})
	}
	meta["cpu"] = cpuinfos
	osName, err := regGetString(
		HKEY_LOCAL_MACHINE,
		`Software\Microsoft\Windows NT\CurrentVersion`,
		`ProductName`)
	if err != nil {
		return err
	}
	osVersion, err := regGetString(
		HKEY_LOCAL_MACHINE,
		`Software\Microsoft\Windows NT\CurrentVersion`,
		`CurrentVersion`)
	if err != nil {
		return err
	}
	osRelease, err := regGetString(
		HKEY_LOCAL_MACHINE,
		`Software\Microsoft\Windows NT\CurrentVersion`,
		`CSDVersion`)
	if err != nil {
		return err
	}

	var memoryStatusEx MEMORYSTATUSEX
	memoryStatusEx.Length = 64
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memoryStatusEx)))
	if r == 0 {
		return err
	}
	meta["memory"] = map[string]string{
		"total": fmt.Sprintf("%dkb", memoryStatusEx.TotalPhys/1024),
		"free":  fmt.Sprintf("%dkb", memoryStatusEx.AvailPhys/1024),
	}

	meta["kernel"] = map[string]string{
		"name":    "Microsoft Windows",
		"os":      osName,
		"version": osVersion,
		"release": osRelease,
	}

	drivebuf := make([]byte, 256)
	_, r, err = procGetLogicalDriveStrings.Call(
		uintptr(len(drivebuf)),
		uintptr(unsafe.Pointer(&drivebuf[0])))
	if r != 0 {
		return err
	}

	drives := []string{}
	for _, v := range drivebuf {
		if v >= 65 && v <= 90 {
			drive := string(v)
			r, _, err = procGetDriveType.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(drive + `:\`))))
			if r != DRIVE_FIXED {
				continue
			}
			c.createCounter(
				fmt.Sprintf(`disk.%s.reads.delta`, drive),
				fmt.Sprintf(`\PhysicalDisk(0 %s:)\Disk Reads/sec`, drive))
			c.createCounter(
				fmt.Sprintf(`disk.%s.writes.delta`, drive),
				fmt.Sprintf(`\PhysicalDisk(0 %s:)\Disk Writes/sec`, drive))
			drives = append(drives, drive+":")
		}
	}

	fsinfos := make(map[string]interface{})
	for _, drive := range drives {
		drivebuf := make([]uint16, 256)
		r, _, err := procQueryDosDevice.Call(
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(drive))),
			uintptr(unsafe.Pointer(&drivebuf[0])),
			uintptr(len(drivebuf)))
		if r == 0 {
			return err
		}
		volumebuf := make([]uint16, 256)
		fsnamebuf := make([]uint16, 256)
		r, _, err = procGetVolumeInformationW.Call(
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(drive+`\`))),
			uintptr(unsafe.Pointer(&volumebuf[0])),
			uintptr(len(volumebuf)),
			0,
			0,
			0,
			uintptr(unsafe.Pointer(&fsnamebuf[0])),
			uintptr(len(fsnamebuf)))
		if r == 0 {
			return err
		}
		freeBytesAvailable := int64(0)
		totalNumberOfBytes := int64(0)
		totalNumberOfFreeBytes := int64(0)
		r, _, err = procGetDiskFreeSpaceEx.Call(
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(drive))),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalNumberOfBytes)),
			uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)))
		if r == 0 {
			continue
		}
		// TODO This should be "C" simply, but currently mackerel.io doesn't handle windows drive path
		fsinfos["/" + drive] = map[string]interface{}{
			"percent_used": fmt.Sprintf("%d%%", 100*freeBytesAvailable/totalNumberOfBytes),
			"kb_used":      (totalNumberOfBytes - totalNumberOfFreeBytes) / 1024 / 1024,
			"kb_size":      totalNumberOfBytes / 1024 / 1024,
			"kb_available": freeBytesAvailable / 1024 / 1024,
			"mount":        drive,
			"label":        syscall.UTF16ToString(drivebuf),
			"volume_name":  syscall.UTF16ToString(volumebuf),
			"fs_type":      strings.ToLower(syscall.UTF16ToString(fsnamebuf)),
		}
	}
	meta["filesystem"] = fsinfos
	meta["status"] = "standby"
	meta["memo"] = ""
	meta["type"] = "unknown"
	info["meta"] = meta

	interfaces := []map[string]string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}

	ai, err := getAdapterList()
	if err != nil {
		return err
	}

	for _, ifi := range ifs {
		addr, err := ifi.Addrs()
		if err != nil {
			return err
		}
		name := ifi.Name
		for ; ai != nil; ai = ai.Next {
			if ifi.Index == int(ai.Index) {
				name = bytePtrToString(&ai.Description[0])
				sname := name
				sname = strings.Replace(sname, "(", "[", -1)
				sname = strings.Replace(sname, ")", "]", -1)
				c.createCounter(
					fmt.Sprintf(`interface.nic%d.rxBytes.delta`, ifi.Index),
					fmt.Sprintf(`\Network Interface(%s)\Bytes Received/sec`, sname))
				c.createCounter(
					fmt.Sprintf(`interface.nic%d.txBytes.delta`, ifi.Index),
					fmt.Sprintf(`\Network Interface(%s)\Bytes Sent/sec`, sname))
			}
		}

		interfaces = append(interfaces, map[string]string{
			"name":       name,
			"ipAddress":  addr[0].String(),
			"macAddress": ifi.HardwareAddr.String(),
		})
	}
	info["interfaces"] = interfaces

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(info)
	if err != nil {
		return err
	}
	if c.Verbose {
		fmt.Println(buf.String())
		fmt.Println()
	}
	endpoint := fmt.Sprintf("%s/api/v0/hosts", c.apibase)
	var req *http.Request
	if c.hostId != "" {
		endpoint += "/" + c.hostId
		req, err = http.NewRequest("PUT", endpoint, &buf)
	} else {
		req, err = http.NewRequest("POST", endpoint, &buf)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apikey)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return errors.New(res.Status)
	}
	defer res.Body.Close()
	var response struct {
		Id string `json:"id"`
	}
	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return err
	}
	c.hostId = response.Id
	return nil
}

func (c *client) collect() []map[string]interface{} {
	r, _, err := procPdhCollectQueryData.Call(uintptr(c.query))
	if r != 0 {
		log.Fatal(err)
	}
	ret := []map[string]interface{}{}

	for k, v := range c.infoMap {
		var value PDH_FMT_COUNTERVALUE_ITEM_DOUBLE
		r, _, err = procPdhGetFormattedCounterValue.Call(uintptr(v.counter), PDH_FMT_DOUBLE, uintptr(0), uintptr(unsafe.Pointer(&value)))
		if r != 0 && r != PDH_INVALID_DATA {
			log.Fatal(err)
		}
		if c.Verbose {
			fmt.Println(k, v.counterName, value.FmtValue.DoubleValue)
		}
		ret = append(ret, map[string]interface{}{
			"hostId": c.hostId,
			"name":   k,
			"time":   time.Now().Unix(),
			"value":  value.FmtValue.DoubleValue,
		})
	}
	return ret
}

func (c *client) postMetricInfo() error {
	infos := c.collect()

	var memoryStatusEx MEMORYSTATUSEX
	memoryStatusEx.Length = 64
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memoryStatusEx)))
	if r == 0 {
		return err
	}

	infos = append(infos, map[string]interface{}{
		"hostId": c.hostId,
		"name":   "memory.total",
		"time":   time.Now().Unix(),
		"value":  memoryStatusEx.TotalPhys / 1024,
	})

	infos = append(infos, map[string]interface{}{
		"hostId": c.hostId,
		"name":   "memory.free",
		"time":   time.Now().Unix(),
		"value":  memoryStatusEx.AvailPhys / 1024,
	})

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(infos)
	if err != nil {
		return err
	}
	if c.Verbose {
		fmt.Println(buf.String())
		fmt.Println()
	}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api/v0/tsdb", c.apibase),
		&buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apikey)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if c.Verbose {
		io.Copy(os.Stdout, res.Body)
		fmt.Println()
	}
	return nil
}

var apibase = flag.String("apibase", "https://mackerel.io", "API base of mackerel")
var apikey = flag.String("apikey", "", "API key")
var verbose = flag.Bool("v", false, "Toggle verbosity")

func main() {
	flag.Parse()

	hostId := ""
	b, err := ioutil.ReadFile("id")
	if err == nil {
		hostId = strings.TrimSpace(string(b))
	}

	c := NewClient(
		*apibase,
		*apikey,
		hostId,
		nil)
	c.Verbose = *verbose

	err = c.postHostInfo()
	if err != nil {
		log.Fatal(err)
	}
	if hostId != c.hostId {
		err = ioutil.WriteFile("id", []byte(c.hostId), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	for {
		err = c.postMetricInfo()
		if err != nil {
			log.Print(err)
		}
		time.Sleep(10 * time.Second)
	}
}
