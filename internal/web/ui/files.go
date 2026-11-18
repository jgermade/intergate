// Package ui is the dashboard's look for other programs' pages, such as
// the desktop app's window: jq79, the default theme (tokens, components,
// icons), the dashboard's stylesheet and its logo. The dashboard serves
// this directory itself, under /ui/.
package ui

import "embed"

//go:embed vendor/jq79.js theme/default/tokens.css theme/default/icons.js theme/default/components app.css logo-mark.svg favicon.svg
var FS embed.FS
