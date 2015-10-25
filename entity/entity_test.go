// Copyright 2015 Tamás Demeter-Haludka
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

package entity

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var funcdef = []Function{
	Function{
		Name: "testFunction",
		Parameters: []FunctionParameter{
			FunctionParameter{
				Name: "a",
			},
			FunctionParameter{
				Name: "b",
			},
		},
		Returns: []FunctionParameter{
			FunctionParameter{
				Name: "c",
			},
			FunctionParameter{
				Name: "d",
			},
		},
	},
	Function{
		Name: "testFunction2",
		Parameters: []FunctionParameter{
			FunctionParameter{
				Name: "a",
			},
			FunctionParameter{
				Name: "b",
			},
		},
		Returns: []FunctionParameter{},
	},
	Function{
		Name: "testFunction3",
		Parameters: []FunctionParameter{
			FunctionParameter{
				Name: "a",
			},
			FunctionParameter{
				Name: "b",
			},
		},
		Returns: []FunctionParameter{},
	},
}

func TestPackageDetection(t *testing.T) {
	Convey("Finds the package name", t, func() {
		So(detectPackageName(), ShouldEqual, "entity")
	})
}

func TestFunctionListing(t *testing.T) {
	Convey("Finds all functions and parameters in the test directory", t, func() {
		wd, _ := os.Getwd()
		defer func() {
			os.Chdir(wd)
		}()

		os.Chdir("test/")

		So(getFunctions(), ShouldResemble, funcdef)
	})
}

func TestFunctionRendering(t *testing.T) {
	Convey("Renders function definitions correctly", t, func() {
		So("c, d = testFunction(a, b)", ShouldEqual, funcdef[0].String())
		So("testFunction2(a, b)", ShouldEqual, funcdef[1].String())
		So("testFunction3(a, b)", ShouldEqual, funcdef[2].String())

		f0 := Function{
			Name: "testSameVariableName",
			Parameters: []FunctionParameter{
				FunctionParameter{
					Name: "a",
				},
			},
			Returns: []FunctionParameter{
				FunctionParameter{
					Name: "_a",
				},
			},
		}

		f1 := Function{
			Name: "testSameVariableName",
			Parameters: []FunctionParameter{
				FunctionParameter{
					Name: "_a",
				},
			},
			Returns: []FunctionParameter{
				FunctionParameter{
					Name: "a",
				},
			},
		}

		So("a = testSameVariableName(a)", ShouldEqual, f0.String())
		So("a = testSameVariableName(a)", ShouldEqual, f1.String())
	})
}

func TestCommentFormatting(t *testing.T) {
	Convey("Formats comments correctly", t, func() {
		e := Entity{
			Comment: "a\nb",
			Fields: []EntityField{
				EntityField{
					Comment: "a",
				},
			},
		}

		So(e.HasComment(), ShouldBeTrue)
		So(e.FormattedComment(), ShouldEqual, "// a\n// b")
		So(e.Fields[0].HasComment(), ShouldBeTrue)
		So(e.Fields[0].FormattedComment(), ShouldEqual, "// a")
	})
}
