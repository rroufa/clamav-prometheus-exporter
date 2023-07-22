/*
Copyright 2020 Christian Niehoff.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package collector

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/r3kzi/clamav-prometheus-exporter/pkg/clamav"
	"github.com/r3kzi/clamav-prometheus-exporter/pkg/commands"
	log "github.com/sirupsen/logrus"
)

// Collector satisfies prometheus.Collector interface
type Collector struct {
	client      clamav.Client
	up          *prometheus.Desc
	threadsLive *prometheus.Desc
	threadsIdle *prometheus.Desc
	threadsMax  *prometheus.Desc
	queue       *prometheus.Desc
	memHeap     *prometheus.Desc
	memMmap     *prometheus.Desc
	memUsed     *prometheus.Desc
	poolsUsed   *prometheus.Desc
	poolsTotal  *prometheus.Desc
	buildInfo   *prometheus.Desc
	databaseAge *prometheus.Desc
}

type VersionInfo struct {
	clamav_version   string
	database_version string
	database_age     float64
	versions_parsed  bool
}

var versionRegex = regexp.MustCompile(`ClamAV+\s([0-9.]*)\/?([0-9.]*)\/?(.*)`)

func GetStat(matches [][]string, index uint) float64 {
	var (
		float float64
		err   error
	)

	if len(matches) > int(index) && len(matches[index]) > 0 {
		float, err = strconv.ParseFloat(matches[index][1], 64)
	} else {
		float = math.NaN()
	}

	if err != nil {
		float = math.NaN()
	}

	return float
}

func GetVersionInfo(version_string string) *VersionInfo {
	versionInfo := VersionInfo{}
	// remove newlines
	version := strings.Replace(version_string, "\n", "", -1)

	matches := versionRegex.FindAllStringSubmatch(string(version), -1)
	strBuilddate := ""

	// Parse version numbers
	if len(matches) > 0 {
		versionInfo.clamav_version = matches[0][1]
		versionInfo.database_version = matches[0][2]
		strBuilddate = matches[0][3]
		versionInfo.versions_parsed = true
	} else {
		log.Error("Error parsing ClamAV Version Numbers")
	}

	// Parse string as date type
	dateFmt := "Mon Jan 2 15:04:05 2006"
	builddate, err := time.Parse(dateFmt, strBuilddate)

	if err != nil {
		log.Errorf("Error parsing ClamAV Database Date: %s", err)
		versionInfo.database_age = math.NaN()
	} else {
		versionInfo.database_age = float64(time.Since(builddate).Seconds())
	}

	return &versionInfo
}

// New creates a Collector struct
func New(client clamav.Client) *Collector {
	return &Collector{
		client:      client,
		up:          prometheus.NewDesc("clamav_up", "Shows UP Status", nil, nil),
		threadsLive: prometheus.NewDesc("clamav_threads_live", "Shows live threads", nil, nil),
		threadsIdle: prometheus.NewDesc("clamav_threads_idle", "Shows idle threads", nil, nil),
		threadsMax:  prometheus.NewDesc("clamav_threads_max", "Shows max threads", nil, nil),
		queue:       prometheus.NewDesc("clamav_queue_length", "Shows queued items", nil, nil),
		memHeap:     prometheus.NewDesc("clamav_mem_heap_bytes", "Shows heap memory usage in bytes", nil, nil),
		memMmap:     prometheus.NewDesc("clamav_mem_mmap_bytes", "Shows mmap memory usage in bytes", nil, nil),
		memUsed:     prometheus.NewDesc("clamav_mem_used_bytes", "Shows used memory in bytes", nil, nil),
		poolsUsed:   prometheus.NewDesc("clamav_pools_used_bytes", "Shows memory used by memory pool allocator for the signature database in bytes", nil, nil),
		poolsTotal:  prometheus.NewDesc("clamav_pools_total_bytes", "Shows total memory allocated by memory pool allocator for the signature database in bytes", nil, nil),
		buildInfo:   prometheus.NewDesc("clamav_build_info", "Shows ClamAV Build Info", []string{"clamav_version", "database_version"}, nil),
		databaseAge: prometheus.NewDesc("clamav_database_age", "Shows ClamAV signature database age in seconds", nil, nil),
	}
}

// Describe satisfies prometheus.Collector.Describe
func (collector *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.up
	ch <- collector.threadsLive
	ch <- collector.threadsIdle
	ch <- collector.threadsMax
	ch <- collector.queue
	ch <- collector.memHeap
	ch <- collector.memMmap
	ch <- collector.memUsed
	ch <- collector.poolsUsed
	ch <- collector.poolsTotal
	ch <- collector.buildInfo
	ch <- collector.databaseAge
}

// Collect satisfies prometheus.Collector.Collect
func (collector *Collector) Collect(ch chan<- prometheus.Metric) {
	pong := collector.client.Dial(commands.PING)
	if bytes.Equal(pong, []byte{'P', 'O', 'N', 'G', '\n'}) {
		ch <- prometheus.MustNewConstMetric(collector.up, prometheus.GaugeValue, 1)
	} else {
		ch <- prometheus.MustNewConstMetric(collector.up, prometheus.GaugeValue, 0)
	}

	stats := collector.client.Dial(commands.STATS)
	idle, err := regexp.MatchString("IDLE", string(stats))
	if err != nil {
		log.Errorf("error searching IDLE field in stats %t: %s", idle, err)
		return
	}
	regex := regexp.MustCompile(`([0-9.]+|N/A)`)
	matches := regex.FindAllStringSubmatch(string(stats), -1)

	if len(matches) > 0 {
		ch <- prometheus.MustNewConstMetric(collector.threadsLive, prometheus.GaugeValue, GetStat(matches, 1))
		ch <- prometheus.MustNewConstMetric(collector.threadsIdle, prometheus.GaugeValue, GetStat(matches, 2))
		ch <- prometheus.MustNewConstMetric(collector.threadsMax, prometheus.GaugeValue, GetStat(matches, 3))
		ch <- prometheus.MustNewConstMetric(collector.queue, prometheus.GaugeValue, GetStat(matches, 5))
	}

	if len(matches) > 0 && !idle {
		ch <- prometheus.MustNewConstMetric(collector.memHeap, prometheus.GaugeValue, GetStat(matches, 7)*1024)
		ch <- prometheus.MustNewConstMetric(collector.memMmap, prometheus.GaugeValue, GetStat(matches, 8)*1024)
		ch <- prometheus.MustNewConstMetric(collector.memUsed, prometheus.GaugeValue, GetStat(matches, 9)*1024)
		ch <- prometheus.MustNewConstMetric(collector.poolsUsed, prometheus.GaugeValue, GetStat(matches, 13)*1024)
		ch <- prometheus.MustNewConstMetric(collector.poolsTotal, prometheus.GaugeValue, GetStat(matches, 14)*1024)
	}

	if len(matches) > 0 && idle {
		ch <- prometheus.MustNewConstMetric(collector.memHeap, prometheus.GaugeValue, GetStat(matches, 8)*1024)
		ch <- prometheus.MustNewConstMetric(collector.memMmap, prometheus.GaugeValue, GetStat(matches, 9)*1024)
		ch <- prometheus.MustNewConstMetric(collector.memUsed, prometheus.GaugeValue, GetStat(matches, 10)*1024)
		ch <- prometheus.MustNewConstMetric(collector.poolsUsed, prometheus.GaugeValue, GetStat(matches, 14)*1024)
		ch <- prometheus.MustNewConstMetric(collector.poolsTotal, prometheus.GaugeValue, GetStat(matches, 15)*1024)
	}

	versionInfo := GetVersionInfo(string(collector.client.Dial(commands.VERSION)))

	if versionInfo.versions_parsed {
		ch <- prometheus.MustNewConstMetric(
			collector.buildInfo,
			prometheus.GaugeValue,
			1,
			versionInfo.clamav_version,
			versionInfo.database_version,
		)
	}

	ch <- prometheus.MustNewConstMetric(collector.databaseAge, prometheus.GaugeValue, versionInfo.database_age)
}