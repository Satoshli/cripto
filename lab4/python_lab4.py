#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laboratorio 4 - Cifrado Simétrico
Implementación de DES, 3DES y AES-256 en modo CBC
"""

from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

# Constantes de tamaños
DES_KEY_SIZE = 8  # bytes
DES_IV_SIZE = 8   # bytes
DES3_KEY_SIZE = 24  # bytes
DES3_IV_SIZE = 8    # bytes
AES_KEY_SIZE = 32   # bytes (AES-256)
AES_IV_SIZE = 16    # bytes

def ajustar_clave(clave, tamano_requerido, nombre_algoritmo):
    """
    Ajusta la clave al tamaño requerido por el algoritmo.
    Si es menor, completa con bytes aleatorios.
    Si es mayor, trunca al tamaño necesario.
    """
    clave_bytes = clave.encode('utf-8')
    longitud_actual = len(clave_bytes)
    
    print(f"\n[{nombre_algoritmo}] Longitud de clave ingresada: {longitud_actual} bytes")
    print(f"[{nombre_algoritmo}] Longitud requerida: {tamano_requerido} bytes")
    
    if longitud_actual < tamano_requerido:
        # Completar con bytes aleatorios
        bytes_faltantes = tamano_requerido - longitud_actual
        bytes_aleatorios = get_random_bytes(bytes_faltantes)
        clave_ajustada = clave_bytes + bytes_aleatorios
        print(f"[{nombre_algoritmo}] Clave completada con {bytes_faltantes} bytes aleatorios")
    elif longitud_actual > tamano_requerido:
        # Truncar la clave
        clave_ajustada = clave_bytes[:tamano_requerido]
        print(f"[{nombre_algoritmo}] Clave truncada a {tamano_requerido} bytes")
    else:
        clave_ajustada = clave_bytes
        print(f"[{nombre_algoritmo}] Clave con longitud exacta")
    
    print(f"[{nombre_algoritmo}] Clave final (hex): {binascii.hexlify(clave_ajustada).decode()}")
    print(f"[{nombre_algoritmo}] Clave final (bytes): {clave_ajustada}")
    
    return clave_ajustada

def ajustar_iv(iv, tamano_requerido, nombre_algoritmo):
    """
    Ajusta el IV al tamaño requerido por el algoritmo.
    """
    iv_bytes = iv.encode('utf-8')
    longitud_actual = len(iv_bytes)
    
    print(f"\n[{nombre_algoritmo}] Longitud de IV ingresado: {longitud_actual} bytes")
    print(f"[{nombre_algoritmo}] Longitud requerida: {tamano_requerido} bytes")
    
    if longitud_actual < tamano_requerido:
        bytes_faltantes = tamano_requerido - longitud_actual
        bytes_aleatorios = get_random_bytes(bytes_faltantes)
        iv_ajustado = iv_bytes + bytes_aleatorios
        print(f"[{nombre_algoritmo}] IV completado con {bytes_faltantes} bytes aleatorios")
    elif longitud_actual > tamano_requerido:
        iv_ajustado = iv_bytes[:tamano_requerido]
        print(f"[{nombre_algoritmo}] IV truncado a {tamano_requerido} bytes")
    else:
        iv_ajustado = iv_bytes
        print(f"[{nombre_algoritmo}] IV con longitud exacta")
    
    print(f"[{nombre_algoritmo}] IV final (hex): {binascii.hexlify(iv_ajustado).decode()}")
    
    return iv_ajustado

def cifrar_des(texto, clave, iv):
    """
    Cifra el texto usando DES en modo CBC.
    """
    print("\n" + "="*60)
    print("CIFRANDO CON DES")
    print("="*60)
    
    clave_ajustada = ajustar_clave(clave, DES_KEY_SIZE, "DES")
    iv_ajustado = ajustar_iv(iv, DES_IV_SIZE, "DES")
    
    cipher = DES.new(clave_ajustada, DES.MODE_CBC, iv_ajustado)
    texto_bytes = texto.encode('utf-8')
    texto_padded = pad(texto_bytes, DES.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"\n[DES] Texto original: {texto}")
    print(f"[DES] Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_ajustada, iv_ajustado

def descifrar_des(texto_cifrado, clave, iv):
    """
    Descifra el texto usando DES en modo CBC.
    """
    print("\n" + "="*60)
    print("DESCIFRANDO CON DES")
    print("="*60)
    
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    texto_padded = cipher.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_padded, DES.block_size)
    
    print(f"[DES] Texto descifrado: {texto_descifrado.decode('utf-8')}")
    
    return texto_descifrado.decode('utf-8')

def cifrar_3des(texto, clave, iv):
    """
    Cifra el texto usando 3DES en modo CBC.
    """
    print("\n" + "="*60)
    print("CIFRANDO CON 3DES")
    print("="*60)
    
    clave_ajustada = ajustar_clave(clave, DES3_KEY_SIZE, "3DES")
    iv_ajustado = ajustar_iv(iv, DES3_IV_SIZE, "3DES")
    
    cipher = DES3.new(clave_ajustada, DES3.MODE_CBC, iv_ajustado)
    texto_bytes = texto.encode('utf-8')
    texto_padded = pad(texto_bytes, DES3.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"\n[3DES] Texto original: {texto}")
    print(f"[3DES] Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_ajustada, iv_ajustado

def descifrar_3des(texto_cifrado, clave, iv):
    """
    Descifra el texto usando 3DES en modo CBC.
    """
    print("\n" + "="*60)
    print("DESCIFRANDO CON 3DES")
    print("="*60)
    
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    texto_padded = cipher.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_padded, DES3.block_size)
    
    print(f"[3DES] Texto descifrado: {texto_descifrado.decode('utf-8')}")
    
    return texto_descifrado.decode('utf-8')

def cifrar_aes256(texto, clave, iv):
    """
    Cifra el texto usando AES-256 en modo CBC.
    """
    print("\n" + "="*60)
    print("CIFRANDO CON AES-256")
    print("="*60)
    
    clave_ajustada = ajustar_clave(clave, AES_KEY_SIZE, "AES-256")
    iv_ajustado = ajustar_iv(iv, AES_IV_SIZE, "AES-256")
    
    cipher = AES.new(clave_ajustada, AES.MODE_CBC, iv_ajustado)
    texto_bytes = texto.encode('utf-8')
    texto_padded = pad(texto_bytes, AES.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"\n[AES-256] Texto original: {texto}")
    print(f"[AES-256] Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_ajustada, iv_ajustado

def descifrar_aes256(texto_cifrado, clave, iv):
    """
    Descifra el texto usando AES-256 en modo CBC.
    """
    print("\n" + "="*60)
    print("DESCIFRANDO CON AES-256")
    print("="*60)
    
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_padded = cipher.decrypt(texto_cifrado)
    texto_descifrado = unpad(texto_padded, AES.block_size)
    
    print(f"[AES-256] Texto descifrado: {texto_descifrado.decode('utf-8')}")
    
    return texto_descifrado.decode('utf-8')

def mostrar_menu():
    """
    Muestra el menú principal del programa.
    """
    print("\n" + "="*60)
    print("LABORATORIO 4 - CIFRADO SIMÉTRICO")
    print("="*60)
    print("\nSeleccione el algoritmo de cifrado:")
    print("1. DES (Clave: 8 bytes, IV: 8 bytes)")
    print("2. 3DES (Clave: 24 bytes, IV: 8 bytes)")
    print("3. AES-256 (Clave: 32 bytes, IV: 16 bytes)")
    print("4. Probar todos los algoritmos")
    print("5. Salir")
    print("="*60)

def solicitar_datos(algoritmo):
    """
    Solicita los datos necesarios al usuario.
    """
    print(f"\n--- Datos para {algoritmo} ---")
    clave = input("Ingrese la clave: ")
    iv = input("Ingrese el vector de inicialización (IV): ")
    texto = input("Ingrese el texto a cifrar: ")
    
    return clave, iv, texto

def main():
    """
    Función principal del programa.
    """
    while True:
        mostrar_menu()
        opcion = input("\nIngrese su opción: ")
        
        if opcion == "1":
            clave, iv, texto = solicitar_datos("DES")
            texto_cifrado, clave_final, iv_final = cifrar_des(texto, clave, iv)
            texto_descifrado = descifrar_des(texto_cifrado, clave_final, iv_final)
            
            print("\n" + "="*60)
            print("RESUMEN DES")
            print("="*60)
            print(f"Texto original: {texto}")
            print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
            print(f"Texto descifrado: {texto_descifrado}")
            print("="*60)
            
        elif opcion == "2":
            clave, iv, texto = solicitar_datos("3DES")
            texto_cifrado, clave_final, iv_final = cifrar_3des(texto, clave, iv)
            texto_descifrado = descifrar_3des(texto_cifrado, clave_final, iv_final)
            
            print("\n" + "="*60)
            print("RESUMEN 3DES")
            print("="*60)
            print(f"Texto original: {texto}")
            print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
            print(f"Texto descifrado: {texto_descifrado}")
            print("="*60)
            
        elif opcion == "3":
            clave, iv, texto = solicitar_datos("AES-256")
            texto_cifrado, clave_final, iv_final = cifrar_aes256(texto, clave, iv)
            texto_descifrado = descifrar_aes256(texto_cifrado, clave_final, iv_final)
            
            print("\n" + "="*60)
            print("RESUMEN AES-256")
            print("="*60)
            print(f"Texto original: {texto}")
            print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
            print(f"Texto descifrado: {texto_descifrado}")
            print("="*60)
            
        elif opcion == "4":
            clave = input("\nIngrese una clave común para todos los algoritmos: ")
            iv = input("Ingrese un IV común: ")
            texto = input("Ingrese el texto a cifrar: ")
            
            # DES
            tc_des, ck_des, iv_des = cifrar_des(texto, clave, iv)
            descifrar_des(tc_des, ck_des, iv_des)
            
            # 3DES
            tc_3des, ck_3des, iv_3des = cifrar_3des(texto, clave, iv)
            descifrar_3des(tc_3des, ck_3des, iv_3des)
            
            # AES-256
            tc_aes, ck_aes, iv_aes = cifrar_aes256(texto, clave, iv)
            descifrar_aes256(tc_aes, ck_aes, iv_aes)
            
            print("\n" + "="*60)
            print("COMPARACIÓN DE RESULTADOS")
            print("="*60)
            print(f"Texto original: {texto}")
            print(f"\nDES cifrado (hex): {binascii.hexlify(tc_des).decode()}")
            print(f"3DES cifrado (hex): {binascii.hexlify(tc_3des).decode()}")
            print(f"AES-256 cifrado (hex): {binascii.hexlify(tc_aes).decode()}")
            print("="*60)
            
        elif opcion == "5":
            print("\n¡Hasta luego!")
            break
        else:
            print("\nOpción inválida. Por favor, intente nuevamente.")
        
        input("\nPresione Enter para continuar...")

if __name__ == "__main__":
    main()
