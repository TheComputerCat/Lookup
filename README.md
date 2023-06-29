# Lookup

En este repositorio se encuentran los scripts que se usaron para la investigación [Descripción de vulnerabilidades presentes en la
infraestructura digital de Organizaciones de
Sociedad Civil de la Comunidad Andina de
Naciones] la recolección de datos públicos de la infraestructura digital de 43 organizaciones no gubernamentales de la Comunidad Andina de Naciones.

## Requisitos de servicios


Para utilizar los scripts existen los siguientes requisitos:

1. Ejecutarlos en una distribución GNU/Linux.

2. Tener instalado Python y pip.

3. Instalar los requerimientos para los scripts (con `pip install -r requirements.txt`).

4. Instalar [Nmap](https://nmap.org/).

Adicionalmente se utilizaron las API de [Shodan](https://help.shodan.io/the-basics/what-is-shodan) que requieren de una cuenta para su uso, la cuenta debe tener membresía o membresía académica. La opción de membresía académica es gratuita para personas pertenecientes a instituciones educativas.

## ¿Cómo se almacena la información?

Para almacenar la información se usa una base de datos [postgreSQL](https://www.postgresql.org/), cuyo esquema se encuentra en ```src/common/model.py```. Para la interacción con la base de datos se uso [SQLAlchemy](https://www.sqlalchemy.org/). En la recolección realizada se usaron solo instancias locales.

## Recolección y procesamiento de los datos

El proceso de recolección de datos consiste en tres grandes pasos:

1. Escaneo de dominios.

2. Escaneo de direcciones IP.

4. Búsqueda de vulnerabilidades.

Cada paso tiene dos etapas:

1. Se obtienen datos y se almacenan sin procesar.

2. Los datos sin procesar son leídos para llenar la base de datos.

Estos procesos se explicaran en mas detalle en la siguiente sección.

## ¿Cómo ejecutar los script?

### Creación de la base de datos

Para crear la base de datos es necesario tener una instancia de PostgreSQL y tener las credenciales de acceso para este. Los scripts reciben las credenciales en un archivo `.ini`. Un ejemplo de la estructura del archivo de credenciales se encuentra en `data_base_config_example.ini`.

Para construir la base de datos se requiere ejecutar el siguiente comando:

    python query_manager.py {credentials-file}

`credentials-file` es la ruta al archivo con las credenciales en el formato esperado (que es como se muestra en `data_base_config.ini`).

Si no cuenta con una instancia, puede desplegar una rápidamente por medio de [Docker](https://www.docker.com/) de la siguiente manera:

    $ docker pull postgres:latest
    $ docker run -d -p 5432:5432  \
        -v postgresVolume:/var/lib/postgresql/data \
        -e POSTGRES_USER={usuario} \
        -e POSTGRES_PASSWORD={contraseña} \
        --name postgresDB postgres \
        -c listen_addresses='*'

Los campos `usuario` y `contraseña` deben coincidir con los que se encuentran en el archivo de configuración.
### Shodan API key

Para la recolección de los datos es necesaria la API key de Shodan en texto plano. Esta puede ser ubicada en la la raíz del proyecto,
### Escaneo de dominios

Los datos con los que se comienza el proceso son dominios de los que se desea obtener información. Para cada uno hacemos una consulta a Shodan, donde se obtiene información general del dominio y sus subdominios. El script `domain_lookup.py` realiza esta tarea. Este script va a guardar todos los datos obtenidos como texto, y luego `domain_extract.py` llenará la base de datos con estos.

Los comandos a ejecutar serían (en el directorio raíz del repositorio):

    python domain_lookup.py lookup {data-dir} {shodan-key} {domain-list}`

1. `data-dir` es la ruta al directorio del sistema donde se desea guardar los datos obtenidos.

2. `shodan-key` es la ruta al archivo donde se encuentra la llave de la API de Shodan, en texto plano.

3. `domain-list` es la ruta al archivo donde se encuentra la lista de dominios a escanear.

Para extraer los datos,

    python domain_extract.py {db-credentials} {data-dir}


1. `db-credentials` es la ruta al archivo donde se encuentran las credenciales para acceder a la base de datos.

2. `data-dir` es la ruta al directorio del sistema donde se encuentran los datos.

### Escaneo de direcciones IP

El flujo es el mismo para la obtención de información de dominios, pero con algunos pasos adicionales. Se necesita una lista de direcciones IP para escanear, y esta puede obtenerse de los datos de dominios sin procesar ejecutando el siguiente comando:

```
python domain_lookup.py get_addresses {data-dir} {ip-list}
```

1. `data-dir` es la ruta al directorio donde se encuentran los pasos sin procesar de los dominios.

2. `ip-list` es la ruta al archivo donde se desea guardar la lista de direcciones IP.

Este script va a generar un archivo de texto de direcciones IP separadas por saltos de línea. Este es el formato que el siguiente script debe recibir.

Cabe aclarar que puede usarse una lista cualquiera de direcciones IP, pues no hay requerimientos sobre su origen. Con una lista de direcciones IP se pueden realizar dos escaneos:

#### Escaneo con Shodan

El escaneo con Shodan se realiza con el comando

```
python host_lookup.py shodan {ip-list} {data-dir} {shodan-key}
```

1. `ip-list` es la ruta al archivo con las direcciones IP a escanear.

2. `data-dir` es la ruta al directorio del sistema donde se desea guardar los datos obtenidos.

3. `shodan-key` es la ruta al archivo donde se encuentra la llave de la API de Shodan, en texto plano.

Para incluir la información obtenida en la base de datos, se debe ejecutar el comando:

```
python host_extract.py {db-credentials} {data-dir}
```

1. `db-credentials` es la ruta al archivo donde se encuentran las credenciales para acceder a la base de datos.

2. `data-dir` es la ruta al directorio del sistema donde se encuentran los datos.

#### Escaneo con Nmap

El escaneo con Nmap se realiza con el comando

```
python host_lookup.py nmap {ip-list} {data-dir} {shodan-key}
```

1. `ip-list` es la ruta al archivo con las direcciones IP a escanear.

2. `data-dir` es la ruta al directorio del sistema donde se desea guardar los datos obtenidos.

Para incluir la información obtenida en la base de datos, se debe ejecutar el comando:

```
python host_extract_nmap.py {db-credentials} {data-dir}
```

1. `db-credentials` es la ruta al archivo donde se encuentran las credenciales para acceder a la base de datos.

2. `data-dir` es la ruta al directorio del sistema donde se encuentran los datos.

### Búsqueda de vulnerabilidades

Para la búsqueda de vulnerabilidades se requiere de una lista de códigos CPE separados por saltos de línea. Para que la API que utilizamos retorne vulnerabilidades asociadas al CPE, es necesario que los códigos incluyan, al menos, información de la versión del software. De otro modo, no se retornará nada.

En este paso no implementamos una forma automática de obtener una lista - algunos códigos CPE se incluyen en la base de datos pero no hay un script para extraerlos y ponerlos en texto. Así, lo recomendable es completar la tabla `SERVICES` con los códigos CPE que faltan, y obtener la lista de ahí. Ya con la lista, para buscar las vulnerabilidades basta ejecutar el siguiente comando:

```
python vulnerabilities_lookup.py {cpe-file} {data-dir}
```

1. `{cpe-file}` es la ruta al archivo con códigos CPE separados por saltos de línea.

2. `{data-dir}` es la ruta al directorio donde los datos se van a guardar.

Para incluir los datos obtenidos en la base de datos hay que ejecutar el siguiente comando:

```
python vulnerabilities_extract.py {db-credentials} {data-dir} cvssMetricV2
```

1. `db-credentials` es la ruta al archivo donde se encuentran las credenciales para acceder a la base de datos.

2. `data-dir` es la ruta al directorio del sistema donde se encuentran los datos.

3. `cvssMetricV2` especifica que se desean introducir los datos de la calificación CVSS 2.0 para las vulnerabilidades.

El script puede recibir un tercer argumento distinto, `cvssMetricV31`, pero no hay una tabla en la base de datos para esta información.

## Creación rápida de la base de datos

Los scripts mencionados anteriormente se pueden ejecutar de manera independiente y tener un control total sobre las ubicaciones de los archivos recolectados.
Sin embargo, puede construir la base de datos unicamente partir de un `.csv` de la siguiente manera:

Estando en la raíz del repositorio, y con ,

    $ mkdir data
    $ cp [dominios.cvs] [ubicaciónRepositorio]/data
    $ make build

La base de datos sera creada y los archivos recolectados serán guardados en `data/`. Si desea guardar los datos o especificar las siguientes variables: 


 - DATA_DIR: ruta al directorio donde están guardados todos los datos recolectados.

 - DOMAIN_LIST_PATH: ruta al directorio donde está guardada la lista de dominios recolectados.

 - SHODAN_API_KEY: ruta al archivo donde se encuentra la llave de la API de Shodan, en texto plano.

 - DB_CONFIG_FILE_PATH: ruta al archivo de configuración .ini de la base de datos.

Para poder asignar estas variables se puede:

Asignar directamente en la construcción:

    $ make build DATA_DIR=valor_de_data_dir SHODAN_API_KEY=valor_de_shodan_api_key

Exportar la variable:

    $ export DB_CONFIG_FILE_PATH=path/to/dbconfig/file

O añadir la linea anterior al archivo .profilerc

## Ejecutar en Docker

Este código puede ser fácilmente ejecutado por medio de [Docker](https://www.docker.com/). Puede encontrar el código utilizado para esto en `dev/`.

Para construir la imagen se debe ejecutar:

    $ make build

Y para lanzar un container interactivo,

    $ make run


## Como correr tests

Este código cuenta con test realizados con el framework de test en python [Unittest](https://docs.python.org/3/library/unittest.html). Estando en la raíz del proyecto, los test se pueden correr de la siguiente manera:

Un único archivo de tests:

    $ python -m unittest src.tests.[nombreArchivoATestear]

Todos los tests en la carpeta `src/tests/`:

    $ python -m unittest discover src/tests/
