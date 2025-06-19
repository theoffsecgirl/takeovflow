package main

import (
	_ "embed"
	"os"
	"os/exec"
)

//go:embed takeovflow.sh
var script string

func main() {
	// Crear un archivo temporal para el script embebido
	tmpfile, err := os.CreateTemp("", "takeovflow-*.sh")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tmpfile.Name())

	// Escribir el contenido del script en el archivo temporal
	_, err = tmpfile.WriteString(script)
	if err != nil {
		panic(err)
	}
	tmpfile.Chmod(0755)
	tmpfile.Close()

	// Ejecutar el script con los argumentos pasados al binario
	cmd := exec.Command("bash", append([]string{tmpfile.Name()}, os.Args[1:]...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}
