// tp is a one-file iperf: a TCP sink and a TCP source that print per-second and
// summary throughput. It replaces iperf3, which is not installed here.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	listen := flag.String("listen", "", "sink: address to listen on")
	connect := flag.String("connect", "", "source: address to connect to")
	dur := flag.Duration("t", 10*time.Second, "source: how long to send")
	flag.Parse()

	switch {
	case *listen != "":
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				start := time.Now()
				n, _ := io.Copy(io.Discard, c)
				el := time.Since(start).Seconds()
				fmt.Printf("receiver: %.1f MB in %.2fs = %.1f Mbit/s\n",
					float64(n)/1e6, el, float64(n)*8/1e6/el)
			}()
		}
	case *connect != "":
		c, err := net.Dial("tcp", *connect)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer c.Close()
		buf := make([]byte, 256<<10)
		start := time.Now()
		deadline := start.Add(*dur)
		var total, mark int64
		next := start.Add(time.Second)
		for time.Now().Before(deadline) {
			n, err := c.Write(buf)
			total += int64(n)
			if err != nil {
				fmt.Fprintln(os.Stderr, "write:", err)
				break
			}
			if now := time.Now(); now.After(next) {
				fmt.Printf("  %2.0fs  %6.1f Mbit/s\n", now.Sub(start).Seconds(),
					float64(total-mark)*8/1e6/now.Sub(next.Add(-time.Second)).Seconds())
				mark = total
				next = now.Add(time.Second)
			}
		}
		el := time.Since(start).Seconds()
		fmt.Printf("sender:   %.1f MB in %.2fs = %.1f Mbit/s\n",
			float64(total)/1e6, el, float64(total)*8/1e6/el)
	default:
		fmt.Fprintln(os.Stderr, "need -listen or -connect")
		os.Exit(2)
	}
}
