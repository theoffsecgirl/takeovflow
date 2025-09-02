# takeovflow

> Subdomain Takeover Scanner Pro
> Versión Go de la herramienta desarrollada por TheOffSecGirl

---

## Descripción

`takeovflow` es un escáner avanzado para detección de **subdomain takeovers**.
Utiliza herramientas externas reconocidas como `subfinder`, `assetfinder`, `subjack`, `httpx`, `dnsx` y `nuclei` para realizar un análisis exhaustivo.

---

## Requisitos

Debes tener instaladas las siguientes herramientas en tu sistema y accesibles en el `PATH`:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [subjack](https://github.com/haccer/subjack)
- [httpx](https://github.com/projectdiscovery/httpx)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- `dig`
- `jq`
- `curl`

Además, el script descargará automáticamente fingerprints para `subjack` si es necesario.

---

## Instalación

1. Clona este repositorio:

   ```
   git clone https://github.com/theoffsecgirl/takeovflow.git
   cd takeovflow
   ```
2. Compila el binario (requiere Go instalado):

   ```
   go build -o takeovflow main.go
   ```
3. (Opcional) Mueve el binario a una carpeta del PATH para uso global:

   ```
   mv takeovflow /usr/local/bin/
   ```

---

## Uso

Ejecuta la herramienta con las opciones que prefieras:

```
./takeovflow -d example.com -t 50 -r 2 -v
```


### Opciones


| Opción       | Descripción                                   |
| ------------- | ---------------------------------------------- |
| -d, --domain  | Escanear un único dominio                     |
| -f, --file    | Archivo con lista de dominios (uno por línea) |
| -l, --list    | Lista de dominios separados por comas          |
| -t, --threads | Número de hilos a usar (por defecto 50)       |
| -r, --rate    | Rate limit para las peticiones (por defecto 2) |
| -v, --verbose | Modo verbose (salida detallada)                |
| -h, --help    | Mostrar ayuda                                  |

---

## Salida

- Se genera un informe Markdown con los resultados, subdominios encontrados y posibles takeovers identificados.
- También se crean logs detallados con el proceso de ejecución.

---

## Contribuciones

Se aceptan contribuciones mediante pull requests. Por favor, abre issues para reportar bugs o sugerir mejoras.

---

## Licencia

Proyecto libre para uso ético y educativo. No se ofrece garantía alguna.

---

### Contacto

Desarrollado por TheOffSecGirl
https://github.com/TheOffSecGirl
