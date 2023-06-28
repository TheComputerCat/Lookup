# Lookup

## Creacion rapida de la base de datos
Los scripts mencionados anteriormente se pueden ejecutar de manera independiente y tener un control total sobre las ubicaciones de los archivos recolectados. 

## Ejecutar en Docker

Este codigo puede ser faclimente ejecutado por medio de [Docker](https://www.docker.com/). Puede encontrar el codigo utilizado para esto en `dev/`.

Para construir la imagen se debe ejecutar:

    $ make build

Y para lanzar un container interactivo,

    $ make run


## Como correr tests

Este codigo cuenta con test realizados con el framework de test en python [Unittest](https://docs.python.org/3/library/unittest.html). Estando en la raíz del proyecto, los test se pueden correr de la siguiente manera:

Un único archivo de tests:

    $ python3 -m unittest src.tests.[nombreArchivoATestear]

Todos los tests en la carpeta `src/tests/`

    $ python -m unittest discover src/tests/
