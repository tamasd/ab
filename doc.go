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
Alien Bunny is a web application framework

This framework dictates a specific way to build websites. This fits websites where the server side rendering is minimal or does not happen at all. A good example is a single page application or a website where the main content is simple to render, and the additional widgets can load later. The framework is designed to work well with ReactJS, but it shouldn't have any issues with other similar client side frameworks (Angular, Durandal etc).

The recommended website structure has 3 parts: the executable, a read-only assets directory containing static assets (compiled js/css, static html pages, robots/humans.txt), and a read-write public directory, that usually contains user-uploaded content. It's planned to add various CDN solutions to serve the assets and the public files. You can configure the assets and the public directory in the ServerConfig struct. The assets directory must have an index.html file.

An application is separated into services (see the Service interface). A service is a functionality unit with its own database schema. Entities (see the entity package for further info) should be services. Services can have providers extending the services' functionality. An example for this is the auth service, which defines a provider interface, that is implemented by several packages under the providers directory, adding support for various 3rd party OAuth services (GitHub, BitBucket, Google, Facebook, Twitter).

The framework contains APIs. These APIs are usually a middleware and a struct in the request context.
*/
package ab
