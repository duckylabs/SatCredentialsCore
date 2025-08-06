# SatCredentialsCore

[![NuGet Version](https://img.shields.io/nuget/v/SatCredentialsCore.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/SatCredentialsCore/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SatCredentialsCore.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/SatCredentialsCore/)

**SatCredentialsCore** es una librería .NET para manejar certificados del SAT en México (.cer y .key), incluyendo validaciones, encriptación, firmas digitales y extracción de datos relevantes.  
Funciona en **.NET 8 y 9** sobre **Windows, Linux y macOS**.

---

## 🚀 Características

- Carga de certificados **.cer** y llaves privadas **.key** en formato PKCS#8 encriptado.
- Validación de:
    - Vigencia del certificado.
    - Correspondencia entre certificado y llave privada.
    - Emisor: Servicio de Administración Tributaria (SAT).
- Obtención de datos clave:
    - RFC y RFC del representante legal.
    - CURP y CURP del representante legal.
    - Razón social y nombre de sucursal.
    - Número de serie del certificado.
- Funciones criptográficas:
    - Firma y verificación con **SHA1** y **SHA256**.
    - Encriptación y desencriptación con **RSA**.
- Exportación de llaves y certificados en:
    - PEM, DER, Base64.
    - PKCS#8 y PKCS#1.

---

## 📦 Instalación

Desde NuGet:

```bash
dotnet add package SatCredentialsCore
```

---

## 🔑 Ejemplo de Uso

```csharp
using SatCredentialsCore;

// Cargar certificado y llave
var certBytes = File.ReadAllBytes("cert.cer");
var keyBytes = File.ReadAllBytes("private_key.key");
var password = "TuPassword";

var credentials = new SatCredentials(certBytes, keyBytes, password);

// Validar datos básicos
Console.WriteLine($"RFC: {credentials.Rfc}");
Console.WriteLine($"Razón Social: {credentials.RazonSocial}");
Console.WriteLine($"Válido hasta: {credentials.ValidTo}");

// Encriptar / Desencriptar
var data = Encoding.UTF8.GetBytes("Mensaje de prueba");
var encrypted = credentials.Encrypt(data);
var decrypted = credentials.Decrypt(encrypted);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));

// Firmar y verificar
var signature = credentials.SingSHA256(data);
var valid = credentials.VerifySHA256(data, signature);
Console.WriteLine($"Firma válida: {valid}");
```

---

## 📂 Requisitos
- Certificado .cer en formato DER.
- Llave privada .key en formato PKCS#8 DER encriptado con contraseña.


---

## 📜 Licencia
Este proyecto está bajo la licencia MIT.
Consulta el archivo LICENSE para más información.