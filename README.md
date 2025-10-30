# takeovflow

> Subdomain Takeover Scanner Pro  
> Versión Python de la herramienta desarrollada por TheOffSecGirl

***

## Descripción

`takeovflow` es un escáner avanzado para detección de **subdomain takeovers**.  
Utiliza herramientas externas reconocidas como `subfinder`, `assetfinder`, `subjack`, `httpx`, `dnsx` y `nuclei` para realizar un análisis exhaustivo de subdominios y servicios vulnerables.

***

## Requisitos

Necesitas tener instalado en tu sistema y accesible en el `PATH`:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [subjack](https://github.com/haccer/subjack)
- [httpx](https://github.com/projectdiscovery/httpx)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- `dig`
- `jq`
- `curl`
- **Python 3** (recomendado >= 3.7)

El script descargará automáticamente fingerprints para `subjack` si es necesario.

***

## Instalación

1. Clona este repositorio:

   ```
   git clone https://github.com/theoffsecgirl/takeovflow.git
   cd takeovflow
   ```

2. Asegúrate de tener Python 3 y las dependencias externas en tu sistema.

3. Dale permisos de ejecución si quieres:

   ```
   chmod +x takeovflow.py
   ```

***

## Uso

Ejecuta el script Python con las opciones que prefieras:

```
python3 takeovflow.py -d example.com -t 50 -r 2 -v
```

### Opciones

| Opción       | Descripción                                     |
| ------------- | ------------------------------------------------|
| -d, --domain  | Escanear un único dominio                       |
| -f, --file    | Archivo con lista de dominios (uno por línea)   |
| -l, --list    | Lista de dominios separados por comas           |
| -t, --threads | Número de hilos a usar (por defecto 50)         |
| -r, --rate    | Rate limit para las peticiones (por defecto 2)  |
| -v, --verbose | Modo verbose (salida detallada)                 |
| -h, --help    | Mostrar ayuda                                   |

***

## Ejemplos de uso

- Escanear dominio único:
  ```
  python3 takeovflow.py -d example.com -v
  ```

- Escanear varios dominios desde archivo:
  ```
  python3 takeovflow.py -f dominios.txt
  ```

- Escanear múltiples dominios separados por coma:
  ```
  python3 takeovflow.py -l "dominio1.com,dominio2.net"
  ```

***

## Salida

- Se genera un informe Markdown con resultados, subdominios encontrados y posibles takeovers identificados.
- También se crean logs detallados con todo el proceso de ejecución.

***

## Contribuciones

Se aceptan contribuciones mediante pull requests.  
Por favor, abre issues para reportar bugs o sugerir mejoras.

***

## Licencia

Proyecto libre para uso ético.  
No se ofrece garantía alguna.

***

## Contacto

Desarrollado por TheOffSecGirl  
[https://github.com/TheOffSecGirl](https://github.com/TheOffSecGirl)

***

¿Te ayudo con otro archivo o texto?
