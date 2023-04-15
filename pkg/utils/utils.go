// Copyright 2023 XImager
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/opencontainers/go-digest"
)

// GetContentLength returns the content length of the request.
func GetContentLength(req *http.Request) (uint64, error) {
	if req == nil {
		return 0, fmt.Errorf("request is nil")
	}
	str := req.Header.Get("Content-Length")
	if str == "" {
		return 0, nil
	}
	length, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("content length is not a number")
	}
	return length, nil
}

// GenPathByDigest generates the path by the digest.
func GenPathByDigest(digest digest.Digest) string {
	hex := digest.Hex()
	return fmt.Sprintf("%s/%s/%s/%s", digest.Algorithm(), hex[0:2], hex[2:4], hex[4:])
}
