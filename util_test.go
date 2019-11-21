package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSectionFromURL(t *testing.T) {
	for _, tt := range []struct {
		desc string
		in   string
		out  string
		err  error
	}{
		{
			in:  "http://my.site.com/pages/create",
			out: "http://my.site.com/pages",
		},
		{
			in:  "http://my.site.com/",
			out: "http://my.site.com/",
		},
		{
			in:  "http://my.site.com/foo/bar/baz",
			out: "http://my.site.com/foo",
		},
		{
			in:  "http://my.site.com",
			out: "http://my.site.com/",
		},
	} {
		actual, err := sectionFromURL(tt.in)
		assert.Equal(t, tt.err, err)
		assert.Equal(t, tt.out, actual)
	}
}
