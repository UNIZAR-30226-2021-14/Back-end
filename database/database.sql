/* todo esto se puede hacer de forma gráfica gracias a la aplicación Postico */

/* 1- creamos la base de datos */
CREATE DATABASE psoftBD;

/* 2- crearemos las tablas */
CREATE TABLE usuarios (
    nombre character varying(50) PRIMARY KEY,
    password character varying(50) NOT NULL
);

/* 3- metemos unos datos de ejemplo para ver que funciona */
INSERT INTO usuarios (nombre,password) VALUES ('juanito@gmail.com','agsh4sd7jad6');

CREATE TABLE contrasenya (
    id SERIAL PRIMARY KEY,
    tipo character varying(50),
    email character varying(50) NOT NULL REFERENCES usuarios(nombre) ON DELETE CASCADE,
    concreteuser character varying(50),
    concretepasswd character varying(50),
    dominio character varying(50),
    fichero bytea
);