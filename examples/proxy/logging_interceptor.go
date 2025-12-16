package main

import (
	"fmt"
	"time"

	"github.com/safedep/pmg/proxy"
)

type loggingInterceptor struct {
	domains []string
}

func newLoggingInterceptor() *loggingInterceptor {
	return &loggingInterceptor{
		domains: []string{
			"registry.npmjs.org",
			"registry.yarnpkg.com",
			"pypi.org",
			"files.pythonhosted.org",
		},
	}
}

func (li *loggingInterceptor) Name() string {
	return "logging-interceptor"
}

func (li *loggingInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	for _, domain := range li.domains {
		if ctx.Hostname == domain {
			return true
		}
	}

	return false
}

func (li *loggingInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	fmt.Printf("LOGGING INTERCEPTOR: [%s] %s %s %s\n",
		ctx.StartTime.Format(time.RFC3339),
		ctx.RequestID,
		ctx.Method,
		ctx.URL.String(),
	)

	return &proxy.InterceptorResponse{
		Action: proxy.ActionAllow,
	}, nil
}
