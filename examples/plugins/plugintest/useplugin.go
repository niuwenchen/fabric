package plugintest

import (
	"fmt"
	"os"
	"plugin"
)

func main() {
	p, err := plugin.Open("/opt/go/src/github.com/hyperledger/fabric/examples/plugins/scc/plugininhello.so")
	if err != nil {
		fmt.Println("error open plugin", err)
		os.Exit(-1)
	}
	s,err := p.Lookup("Hello")
	if hello,ok := s.(func()); ok{
		hello()
	}
}
