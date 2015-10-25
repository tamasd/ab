/*
The main package behind the entity generation.

This system is optional. It generates a model, basic database CRUD and a REST CRUD. Most of the generated code is extendable with hooks. You can see the possible hooks in the generated source as commented out function calls, prefixed with HOOK.

In order to implement a hook, you have to create a function somewhere in the package with the same name as the hook. This function has some restrictions: all input and output parameters must have a name. the reason for this is because the generated hook invocation will use these parameters as variables.

Let's see an example. You see a comment in the generated source:

	func (s *Service) SchemaInstalled(db ab.DB) bool {
		found := ab.TableExists(db, "test")

		// HOOK: afterTestSchemaInstalled()

		return found
	}

What you want to do is to make sure that this function reports that a different table is also exists in the schema. What you have to do is to override the "found" variable. The correct solution for this is to put this function into the package (but not in the generated files):

	func afterTestSchemaInstalled(db ab.DB, found bool) (_found bool) {
		return found && ab.TableExists(db, "testx")
	}

If you rerun the ab-entity tool (preferably through go generate), the function before will change to this:

	func (s *Service) SchemaInstalled(db ab.DB) bool {
		found := ab.TableExists(db, "test")

		found = afterTestSchemaInstalled(db, found)

		return found
	}

Look at the name of the input and output parameters in the hook implementation. The parameters' name will be used as the variable names when the hook is called. This means that any variable in the scope can be used. New variables can't be declared. In order to avoid the duplicate parameter error, if you start a variable with an underscore, the first underscore will be omitted.

The hook generator (and the entity generator itself) is a simple tool to generate source code from templates. It does not validate the generated source code, and it is not capable of code analysis.
*/
package entity
