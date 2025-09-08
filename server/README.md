<p align="center">
   <h1 align="center">Servidor SM-DP+</h1>
</p>

<p align="center">
  Este servidor implementa las funciones <i>InitiateAuthentication</i>, <i>AuthenticateClient</i> y <i>GetBoundProfilePackage</i> del SM-DP+, descritas en el estándar RSP definido por la GSMA en el documento <a href="https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/12/SGP.22-v3.1.pdf" target="blank">SGP.22</a>.
</p>

---

Para ejecutar el servidor, se deben instalar las dependencias en un entorno de `Python 3` de la siguiente manera:

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Además, se debe tener un directorio llamado `certificates` con los certificados necesarios. A continuación, se explica cómo obtener certificados de prueba según el documento <a href="https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2025/01/SGP.26-3.0.2.pdf" target="blank">SGP.26</a> de la GSMA.

### Certificado de CA

Se obtiene la clave privada `ca_key.pem`:
```
openssl ecparam -name prime256v1 -genkey -out ca_key.pem
```

Se genera el fichero de configuración `ca.cnf` con el siguiente contenido:
```
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = Test CI
OU = TESTCERT
O = RSPTEST
C = IT

[ v3_req ]
subjectKeyIdentifier = hash
keyUsage = critical, keyCertSign, cRLSign
certificatePolicies = 2.23.146.1.2.1.0
basicConstraints = critical, CA:true
subjectAltName = RID:2.999.1
```

Se obtiene el certificado `ca_cert.pem` con la siguiente instrucción:
```
openssl req -config ca.cnf -key ca_key.pem -new -x509 -days 12783 -sha256 -set_serial 0x00B874F3ABFA6C44D3 -extensions v3_req -out ca_cert.pem
```

### Certificado de autenticación

Se obtiene la clave privada `smdp_auth_key.pem`:
```
openssl ecparam -name prime256v1 -genkey -out smdp_auth_key.pem
```

Se crea el fichero de configuración `smdp_auth.cnf` con el siguiente contenido:
```
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = ACME
CN = TEST SM-DP+ 1
```

Se genera la solicitud de firma `smdp_auth.csr`:
```
openssl req -new -nodes -sha256 -config smdp_auth.cnf -key smdp_auth_key.pem -out smdp_auth.csr
```

Se crea el archivo de extensiones `smdp_auth_ext.cnf` con el siguiente contenido:
```
[ extensions ]
authorityKeyIdentifier = keyid, issuer
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature
certificatePolicies = critical, 2.23.146.1.2.1.4
subjectAltName = RID:2.999.10
```

Se genera el certificado `smdp_auth_cert.pem` firmando la solicitud con la clave privada de la CA:
```
openssl x509 -req -in smdp_auth.csr -CA ca_cert.pem -CAkey ca_key.pem -set_serial 0x100 -days 1095 -extfile smdp_auth_ext.cnf -out smdp_auth_cert.pem
```

### Certificado de vinculación de perfiles

Se obtiene la clave privada `smdp_pb_key.pem`:
```
openssl ecparam -name prime256v1 -genkey -out smdp_pb_key.pem
```

Se crea el fichero de configuración `smdp_pb.cnf` con el siguiente contenido:
```
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = ACME
CN = TEST SM-DP+ 1
```

Se genera la solicitud de firma `smdp_pb.csr`:
```
openssl req -new -nodes -sha256 -config smdp_pb.cnf -key smdp_pb_key.pem -out smdp_pb.csr
```

Se crea el archivo de extensiones `smdp_pb_ext.cnf` con el siguiente contenido:
```
[ extensions ]
authorityKeyIdentifier = keyid, issuer
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature
certificatePolicies = critical, 2.23.146.1.2.1.5
subjectAltName = RID:2.999.10
```

Se genera el certificado `smdp_auth_cert.pem` firmando la solicitud con la clave privada de la CA:
```
openssl x509 -req -in smdp_pb.csr -CA ca_cert.pem -CAkey ca_key.pem -set_serial 0x101 -days 1095 -extfile smdp_pb_ext.cnf -out smdp_pb_cert.pem
```

### Certificado de TLS

Cabe mencionar que el servidor se ha ejecutado en una instancia (<i>droplet</i>) de `DigitalOcean` utilizando `Nginx` y un certificado de TLS de `Let's Encrypt`. Además, se ha registrado un dominio para alojar el servicio.

Para generar este certificado, se ejecuta la siguiente instrucción:
```
sudo certbot --nginx -d <dominio_resevado>
```
