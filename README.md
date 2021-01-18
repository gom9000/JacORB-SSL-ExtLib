# JacORB SSL-ExtLib #

A JacORB SSL features extends library
that provides a Socket and ServerSocket factory implementation that allows to create sockets that support SSL and port range.


## Prerequisities
* JacORB 2.2.4 libraries
* Java 1.6 or later


## Building Source
The project may be imported into IDE tool (as Eclipse, IntelliJ or others) using standard import commands.
Remember to include JacORB libraries to the classpath.


## Installation
JacORB SSL-ExtLib should work under JacORB 2.2.4 (See [here](http://www.jacorb.org)).
The built library, maybe `jacorb-ssl-extlib.jar`, must be included to the classpath, and the following parameters in the jacorb configuration file:

#### Socket port range parameters:

	jacorb.ssl.socket_factory=net.gos95.jacorb.ssl.PortRangeSSLSocketFactory
	jacorb.ssl.socket_factory.port.min=...
	jacorb.ssl.socket_factory.port.max=...

#### ServerSocket port range parameters:

	jacorb.ssl.server_socket_factory=net.gos95.jacorb.ssl.PortRangeSSLServerSocketFactory
	jacorb.ssl.server_socket_factory.port.min=...
	jacorb.ssl.server_socket_factory.port.max=...


## Links
The JacORB main home page is [here](http://www.jacorb.org).
