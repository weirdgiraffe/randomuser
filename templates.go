//
// templates.go
// Copyright (C) 2017 weirdgiraffe <giraffe@cyberzoo.xyz>
//
// Distributed under terms of the MIT license.
//

package main

import "html/template"

var indexHTML = template.Must(template.New("authorized").Parse(`
<html>
	<body>
	{{ if .Authorized }}
	<p>Hello, <b>{{ .User }}</b> !</p>
	{{ else }}
	<p>Log in with <a href="/oauth">GitHub</a></p>
	{{ end }}
	</body>
</html>
`))
