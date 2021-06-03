package errcode

import (
	"fmt"
	"net/http"
)

type ErrCode struct {
	Status int
	Code   int
	Msg    string
}

func (e *ErrCode) Error() string {
	if e.Code == 0 {
		msg := e.Msg
		if msg == "" {
			msg = http.StatusText(e.Status)
		}
		return fmt.Sprintf("status: %d, msg: %s", e.Status, msg)
	}
	return fmt.Sprintf("status: %d, code: %d, msg: %s", e.Status, e.Code, e.Msg)
}
