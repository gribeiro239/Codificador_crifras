# Codificador de Cifras (PyQt5)

Aplicativo desktop em Python que **encripta e decodifica** textos usando **César**, **Atbash**, **Numérica (A1Z26)** e **Vigenère**.  
Interface em **PyQt5** com **validação de chaves**, **modo claro/escuro** e **mensagens de erro**. O app converte o texto para **maiúsculas** e altera apenas letras **A–Z**, preservando espaços e pontuação.

## Recursos
- Quatro cifras clássicas: César, Atbash, Numérica (A1Z26) e Vigenère
- Encriptar/Decodificar com um clique
- Validação automática de chave (int para César; apenas letras para Vigenère)
- Tema claro/escuro e feedback de erros

## Instalação e uso
```bash
pip install PyQt5
python main.py
