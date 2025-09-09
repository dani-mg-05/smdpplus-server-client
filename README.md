<p align="center">
   <h1 align="center">SM-DP+ (Servidor y Cliente)</h1>
</p>

<p align="center">
  Este repositorio forma parte de mi Trabajo Fin de Máster (TFM) del máster en Ciberseguridad de la Universidad de Alcalá (UAH) titulado <strong>Análisis de seguridad en el proceso de provisión de eSIMs a través de la implementación de un servidor SM-DP+</strong>.
</p>

---

<p align="justify">
El contenido de este proyecto se divide en:
  <ul>
    <li><strong>Servidor</strong>: Ejecuta las funciones <i>InitiateAuthentication</i>, <i>AuthenticateClient</i> y <i>GetBoundProfilePackage</i> del SM-DP+, descritas en el estándar RSP definido por la GSMA en el documento <a href="https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/12/SGP.22-v3.1.pdf" target="blank">SGP.22</a>. Está programado en Python 3 con el framework FastAPI.</li>
    <li><strong>Cliente</strong>: Prepara las peticiones para ejecutar de manera correcta el servidor y comprobar su funcionamiento. Está programado en Android Studio con el lenguaje de programación Java.</li>
  </ul>
</p>

<p align="justify">
  Para ejecutar correctamente el Servidor y el Cliente, se describen los pasos en los archivos <strong>README.md</strong> que se encuentran dentro de cada uno de los directorios de este repositorio.
</p>
