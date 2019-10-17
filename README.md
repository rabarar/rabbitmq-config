

## RabbitMQ Configuration for OSX 

### The goal is to configure rabbitmq so that only SSL connections are serviced - for both clients as well as websockets (STOMP)

File Locations:

Configuration files are located at:

```
/usr/local/etc/rabbitmq/
```

Log files are located at:
```
/usr/local/var/log/rabbitmq/
```

1 install with brew:
	brew install rabbitmq

2 run using brew services

	brew services start rabbitmq

3 config file location on OSX
	/usr/local/etc/rabbitmq/rabbitmq.config
	/usr/local/etc/rabbitmq/advanced.config

4 configure TLS
		# wget https://github.com/michaelklishin/tls-gen/archive/master.zip 
		# unzip master.zip
		# cd tls-get-master/basic

		# chown -R rabbitmq: /etc/rabbitmq/testca
		# chown -R rabbitmq: /etc/rabbitmq/server
		# chown -R rabbitmq: /etc/rabbitmq/client

		add to the config file:

				[
				  {ssl, [{versions, ['tlsv1.2', 'tlsv1.1', tlsv1]}]},
				  {rabbit, [
					 {ssl_listeners, [5671]},
					 {ssl_options, [{cacertfile,"/etc/rabbitmq/testca/cacert.pem"},
									{certfile,"/etc/rabbitmq/server/cert.pem"},
									{keyfile,"/etc/rabbitmq/server/key.pem"},
							{versions, ['tlsv1.2', 'tlsv1.1', tlsv1]},
							{ciphers,  ["ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES256-GCM-SHA384",
							 "ECDHE-ECDSA-AES256-SHA384","ECDHE-RSA-AES256-SHA384",
							 "ECDH-ECDSA-AES256-GCM-SHA384","ECDH-RSA-AES256-GCM-SHA384",
							 "ECDH-ECDSA-AES256-SHA384","ECDH-RSA-AES256-SHA384",
							 "DHE-RSA-AES256-GCM-SHA384","DHE-DSS-AES256-GCM-SHA384",
							 "DHE-RSA-AES256-SHA256","DHE-DSS-AES256-SHA256","AES256-GCM-SHA384",
							 "AES256-SHA256","ECDHE-ECDSA-AES128-GCM-SHA256",
							 "ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES128-SHA256",
							 "ECDHE-RSA-AES128-SHA256","ECDH-ECDSA-AES128-GCM-SHA256",
							 "ECDH-RSA-AES128-GCM-SHA256","ECDH-ECDSA-AES128-SHA256",
							 "ECDH-RSA-AES128-SHA256","DHE-RSA-AES128-GCM-SHA256",
							 "DHE-DSS-AES128-GCM-SHA256","DHE-RSA-AES128-SHA256","DHE-DSS-AES128-SHA256",
							 "AES128-GCM-SHA256","AES128-SHA256","ECDHE-ECDSA-AES256-SHA",
							 "ECDHE-RSA-AES256-SHA","DHE-RSA-AES256-SHA","DHE-DSS-AES256-SHA",
							 "ECDH-ECDSA-AES256-SHA","ECDH-RSA-AES256-SHA","AES256-SHA",
							 "ECDHE-ECDSA-DES-CBC3-SHA","ECDHE-RSA-DES-CBC3-SHA","EDH-RSA-DES-CBC3-SHA",
							 "EDH-DSS-DES-CBC3-SHA","ECDH-ECDSA-DES-CBC3-SHA","ECDH-RSA-DES-CBC3-SHA",
							 "DES-CBC3-SHA","ECDHE-ECDSA-AES128-SHA","ECDHE-RSA-AES128-SHA",
							 "DHE-RSA-AES128-SHA","DHE-DSS-AES128-SHA","ECDH-ECDSA-AES128-SHA",
							 "ECDH-RSA-AES128-SHA","AES128-SHA","EDH-RSA-DES-CBC-SHA","DES-CBC-SHA"]},
							 {verify,verify_none},
									 {fail_if_no_peer_cert,false}]}]}
				].


5 enable management UI

```
			rabbitmq-plugins enable rabbitmq_management 
```

6  enable Eternal SASL authentication using X509 CN Certs


```
		   {rabbit, [
		        {auth_mechanisms, ['EXTERNAL']},
		        {ssl_listeners, [5671]},
		        {ssl_cert_login_from, common_name},

			...
```


	Then in the golang code use DialConfig()

	

```
		// implement Authentication interface
		type ExternalAuth struct {
		}

		func (e ExternalAuth) Mechanism() string {
			return "EXTERNAL"
		}

		func (e ExternalAuth) Response() string {
			return "EXTERNAL"
		}
```


	Dial as follows (make sure to add a username that matches the CN in the PKI Cert
	And make sure the user has access to the Virtual Host

```
	conn, err := amqp.DialConfig("amqps://@mbp2018-8.local:5671",
		amqp.Config{
			SASL:            []amqp.Authentication{ExternalAuth{}},
			Vhost:           "/",
			TLSClientConfig: cfg,
		})
```


7 Web STOMP SSL Config 

```
		{rabbitmq_web_stomp,
			  [{ssl_config, [{port,       15673},
							 {backlog,    1024},
							 {cacertfile, "/path/to/ca_certificate.pem"},
							 {certfile,   "/path/to/server_certificate.pem"},
							 {keyfile,    "/path/to/server_key.pem"},
							 %% needed when private key has a passphrase
							 {password,   "changeme"}]}]}
```


