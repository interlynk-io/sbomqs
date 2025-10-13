package extractors

import (
	"fmt"
	"strings"
)

func textual(x interface{}) string {
	return strings.TrimSpace(fmt.Sprint(x))
}
