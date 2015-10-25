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

/*
Entity generator tool.
*/
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/tamasd/ab/entity"
	"golang.org/x/tools/imports"
)

func main() {
	abCmd := &cobra.Command{
		Use:   "ab",
		Short: "ab is a command line helper for the Alien Bunny framework",
	}

	abCmd.AddCommand(
		createEntityCmd(),
	)

	abCmd.Execute()
}

func createEntityCmd() *cobra.Command {
	entityCmd := &cobra.Command{
		Use:   "entity",
		Short: "entity generator",
	}

	var (
		genstruct            = entityCmd.Flags().Bool("generate-struct", true, "Generate a struct")
		output               = entityCmd.Flags().String("output", "entity.go", "Output file. Use - for stdout.")
		pkg                  = entityCmd.Flags().String("package", "", "Package name. Leave empty for auto detect.")
		gencrudinsert        = entityCmd.Flags().Bool("generate-crud-insert", true, "Generate CRUD insert")
		gencrudupdate        = entityCmd.Flags().Bool("generate-crud-update", true, "Generate CRUD update")
		gencruddelete        = entityCmd.Flags().Bool("generate-crud-delete", true, "Generate CRUD delete")
		gencrudload          = entityCmd.Flags().Bool("generate-crud-load", true, "Generate CRUD load")
		genservice           = entityCmd.Flags().Bool("generate-service", true, "Generate service")
		genservicestruct     = entityCmd.Flags().Bool("generate-service-struct", true, "Generate empty service type (structure).")
		genservicestructname = entityCmd.Flags().String("generate-service-struct-name", "Service", "Name of the empty service type.")
		genservicelist       = entityCmd.Flags().Bool("generate-service-list", true, "Generate a listing endpoint")
		genserviceget        = entityCmd.Flags().Bool("generate-service-get", true, "Generate a get endpoint")
		genservicepost       = entityCmd.Flags().Bool("generate-service-post", true, "Generate a post endpoint")
		genserviceput        = entityCmd.Flags().Bool("generate-service-put", true, "Generate a put endpoint")
		genservicepatch      = entityCmd.Flags().Bool("generate-service-patch", true, "Generate a patch endpoint")
		genservicedelete     = entityCmd.Flags().Bool("generate-service-delete", true, "Generate a delete endpoint")
		generatesql          = entityCmd.Flags().Bool("generate-sql", true, "Generate a service schema")
		urlidfield           = entityCmd.Flags().Uint("urlidfield", 0, "Index of the URL ID field.")
		idfield              = entityCmd.Flags().Uint("idfield", 0, "Index of the ID field.")
	)

	entityCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			cmd.Usage()
			return
		}

		entityName := args[0]

		e, err := entity.GetEntity(entityName)
		e.URLIDField = *urlidfield
		e.IDField = *idfield
		if err != nil {
			log.Fatalln(err)
		}

		et := entity.EntityTemplate{
			Entity:         e.Normalized(),
			Package:        *pkg,
			GenerateStruct: *genstruct,
			GenerateCRUD: entity.EntityCRUD{
				Insert: *gencrudinsert,
				Update: *gencrudupdate,
				Delete: *gencruddelete,
				Load:   *gencrudload,
			},
			GenerateSQL: *generatesql,
		}

		if *genservice {
			et.GenerateService = entity.EntityService{
				Struct:     *genservicestruct,
				StructName: *genservicestructname,
				List:       *genservicelist,
				Get:        *genserviceget,
				Post:       *genservicepost,
				Put:        *genserviceput,
				Patch:      *genservicepatch,
				Delete:     *genservicedelete,
			}
		}

		rendered := et.String()
		processed, err := imports.Process("", []byte(rendered), nil)
		if err != nil {
			log.Fatalln(err)
		}
		rendered = string(processed)
		if *output == "-" {
			fmt.Println(rendered)
		} else {
			f, err := os.Create(*output)
			if err != nil {
				log.Fatalln(err)
			}
			defer f.Close()

			_, err = f.WriteString(rendered)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}

	return entityCmd
}
