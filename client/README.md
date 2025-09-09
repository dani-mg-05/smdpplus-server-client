<p align="center">
   <h1 align="center">Cliente SM-DP+</h1>
</p>

<p align="center">
  Esta aplicación agrupa parte de las funciones de un LPA y de una eUICC para verificar el funcionamiento del servidor SM-DP+, generando las peticiones necesarias para ejecutar las funciones <i>InitiateAuthentication</i>, <i>AuthenticateClient</i> y <i>GetBoundProfilePackage</i> del servidor, descritas en el estándar RSP definido por la GSMA en el documento <a href="https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/12/SGP.22-v3.1.pdf" target="blank">SGP.22</a>. Está programado en Android Studio con el lenguaje de programación Java.
</p>

---

Para ejecutar la aplicación, se deben generar los certificados necesarios (EUM y eUICC) en el directorio \
`Cliente_SM-DP+/app/src/main/assets/`. A continuación, se explica cómo obtener certificados de prueba según el documento <a href="https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2025/01/SGP.26-3.0.2.pdf" target="blank">SGP.26</a> de la GSMA.

### Certificado de CA

Debe ser el mismo que el del servidor, definido en el archivo `README.md` del directorio <a href="https://github.com/dani-mg-05/smdpplus-server-client/tree/main/server" target="blank">server</a>.

### Certificado del EUM

Se obtiene la clave privada `eum_key.pem`:
```
openssl ecparam -name prime256v1 -genkey -out eum_key.pem
```

Se crea el fichero de configuración `eum.cnf` con el siguiente contenido:
```
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = RSP Test EUM
CN = EUM Test
C = ES
```

Se genera la solicitud de firma `eum.csr`:
```
openssl req -new -nodes -sha256 -config eum.cnf -key eum_key.pem -out eum.csr
```

Se crea el archivo de extensiones `eum_ext.cnf` con el siguiente contenido:
```
[ extensions ]
authorityKeyIdentifier = issuer, keyid
subjectKeyIdentifier = hash
keyUsage = critical, keyCertSign
certificatePolicies = critical, 2.23.146.1.2.1.2
basicConstraints = critical, CA:true, pathLenConstraint:0
subjectAltName = RID:2.999.5
```

Se genera el certificado `eum_cert.pem` firmando la solicitud con la clave privada de la CA:
```
openssl x509 -req -in eum.csr -CA ca_cert.pem -CAkey ca_key.pem -set_serial 0x12345678 -days 12410 -extfile eum_ext.cnf -out eum_cert.pem
```

### Certificado de la eUICC

Se obtiene la clave privada `euicc_key.pem`:
```
openssl ecparam -name prime256v1 -genkey -out euicc_key.pem
```

Se crea el fichero de configuración `euicc.cnf` con el siguiente contenido:
```
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = RSP Test EUM
CN = Test eUICC
C = ES
```

Se genera la solicitud de firma `euicc.csr`:
```
openssl req -new -nodes -sha256 -config euicc.cnf -key euicc_key.pem -out euicc.csr
```

Se crea el archivo de extensiones `euicc_ext.cnf` con el siguiente contenido:
```
[ extensions ]
authorityKeyIdentifier = keyid, issuer
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature
certificatePolicies = critical, 2.23.146.1.2.1.1
```

Se genera el certificado `euicc_cert.pem` firmando la solicitud con la clave privada de la CA:
```
openssl x509 -req -in euicc.csr -CA eum_cert.pem -CAkey eum_key.pem -set_serial 0x020000000000000001 -days 2000000 -extfile euicc_ext.cnf -out euicc_cert.pem
```

