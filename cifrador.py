import sys
import string
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QTextEdit,
    QPushButton, QComboBox, QVBoxLayout, QHBoxLayout, QRadioButton,
    QButtonGroup, QGroupBox, QMessageBox
)
from PyQt5.QtGui import QIcon, QIntValidator

# === Funções de cifra ===


def cifra_cesar(texto, chave, modo='enc'):
    resultado = ''
    for char in texto.upper():
        if char in string.ascii_uppercase:
            base = ord('A')
            deslocamento = chave if modo == 'enc' else -chave
            nova_letra = chr((ord(char) - base + deslocamento) % 26 + base)
            resultado += nova_letra
        else:
            resultado += char
    return resultado


def cifra_atbash(texto):
    resultado = ''
    for char in texto.upper():
        if char in string.ascii_uppercase:
            nova_letra = chr(ord('Z') - (ord(char) - ord('A')))
            resultado += nova_letra
        else:
            resultado += char
    return resultado


def cifra_numerica(texto, modo='enc'):
    resultado = ''
    if modo == 'enc':
        for char in texto.upper():
            if char in string.ascii_uppercase:
                resultado += str(ord(char) - ord('A') + 1) + ' '
            else:
                resultado += char
    else:
        partes = texto.split()
        for parte in partes:
            if parte.isdigit():
                resultado += chr(int(parte) + ord('A') - 1)
            else:
                resultado += parte
    return resultado.strip()


def cifra_vigenere(texto, chave, modo='enc'):
    alfabeto = string.ascii_uppercase
    texto = texto.upper()
    chave = chave.upper()
    resultado = ''
    chave_index = 0

    for char in texto:
        if char in alfabeto:
            t = ord(char) - ord('A')
            k = ord(chave[chave_index % len(chave)]) - ord('A')
            if modo == 'enc':
                c = (t + k) % 26
            else:
                c = (t - k + 26) % 26
            resultado += chr(c + ord('A'))
            chave_index += 1
        else:
            resultado += char

    return resultado

# === Interface gráfica com PyQt5 ===


class CifraApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Codificador de Cifras")
        self.setWindowIcon(QIcon("img/icone.png"))
        self.escuro = False
        self.setStyleSheet(self.estilo_claro())
        self.init_ui()

    def estilo_claro(self):
        return """
        QWidget {
            background-color: #f7f7f7;
            font-family: Arial;
            font-size: 14px;
        }
        QTextEdit, QLineEdit {
            background-color: white;
            border: 1px solid #ccc;
            padding: 6px;
            border-radius: 4px;
        }
        QPushButton {
            background-color: #007acc;
            color: white;
            border: none;
            padding: 8px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #005f99;
        }
        """

    def estilo_escuro(self):
        return """
        QWidget {
            background-color: #2e2e2e;
            color: white;
            font-family: Arial;
            font-size: 14px;
        }
        QTextEdit, QLineEdit {
            background-color: #3b3b3b;
            color: white;
            border: 1px solid #555;
            padding: 6px;
            border-radius: 4px;
        }
        QPushButton {
            background-color: #444;
            color: white;
            border: none;
            padding: 8px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #666;
        }
        """

    def toggle_tema(self):
        self.escuro = not self.escuro
        if self.escuro:
            self.setStyleSheet(self.estilo_escuro())
            self.toggle_button.setText("Modo Claro")
        else:
            self.setStyleSheet(self.estilo_claro())
            self.toggle_button.setText("Modo Escuro")

    def init_ui(self):
        layout = QVBoxLayout()

        grupo_entrada = QGroupBox("Entrada")
        entrada_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        self.text_input.setToolTip("Texto que será cifrado ou decifrado")
        entrada_layout.addWidget(QLabel("Digite o texto:"))
        entrada_layout.addWidget(self.text_input)
        grupo_entrada.setLayout(entrada_layout)
        layout.addWidget(grupo_entrada)

        grupo_opcao = QGroupBox("Opções")
        opcao_layout = QVBoxLayout()

        radio_layout = QHBoxLayout()
        self.radio_group = QButtonGroup()
        self.radio_encrypt = QRadioButton("Encriptar")
        self.radio_decrypt = QRadioButton("Decodificar")
        self.radio_encrypt.setChecked(True)
        self.radio_group.addButton(self.radio_encrypt)
        self.radio_group.addButton(self.radio_decrypt)
        radio_layout.addWidget(self.radio_encrypt)
        radio_layout.addWidget(self.radio_decrypt)
        opcao_layout.addLayout(radio_layout)

        self.cipher_select = QComboBox()
        self.cipher_select.addItems(
            ["César", "Atbash", "Numérica (A1Z26)", "Vigenère"])
        self.cipher_select.currentIndexChanged.connect(
            self.atualizar_estado_chave)
        self.cipher_select.setToolTip("Escolha a cifra desejada")
        opcao_layout.addWidget(QLabel("Escolha a cifra:"))
        opcao_layout.addWidget(self.cipher_select)

        self.key_label = QLabel("Chave (se aplicável):")
        opcao_layout.addWidget(self.key_label)

        self.key_input = QLineEdit()
        self.key_input.setToolTip(
            "Informe a chave (somente para cifras que exigem)")
        opcao_layout.addWidget(self.key_input)

        grupo_opcao.setLayout(opcao_layout)
        layout.addWidget(grupo_opcao)

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        layout.addWidget(QLabel("Resultado:"))
        layout.addWidget(self.result_output)

        self.process_button = QPushButton("Executar")
        self.process_button.clicked.connect(self.processar)
        layout.addWidget(self.process_button)

        self.toggle_button = QPushButton("Modo Escuro")
        self.toggle_button.clicked.connect(self.toggle_tema)
        layout.addWidget(self.toggle_button)

        self.setLayout(layout)
        self.atualizar_estado_chave()

    def atualizar_estado_chave(self):
        cifra = self.cipher_select.currentText()
        if cifra == "César":
            self.key_input.setDisabled(False)
            self.key_input.setValidator(QIntValidator(-99, 99))
            self.key_input.setPlaceholderText("Ex: -2")
            self.key_label.setText("Chave (ex: -2):")
        elif cifra in ["Atbash", "Numérica (A1Z26)"]:
            self.key_input.setDisabled(True)
            self.key_input.setValidator(None)
            self.key_input.setPlaceholderText("")
            self.key_label.setText("Chave (não aplicável):")
        else:
            self.key_input.setDisabled(False)
            self.key_input.setValidator(None)
            self.key_input.setPlaceholderText("")
            self.key_label.setText("Chave (se aplicável):")

    def mostrar_erro(self, mensagem):
        box = QMessageBox()
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("Erro")
        box.setText(mensagem)
        box.exec_()

    def processar(self):
        texto = self.text_input.toPlainText()
        modo = 'enc' if self.radio_encrypt.isChecked() else 'dec'
        cifra = self.cipher_select.currentText()
        chave = self.key_input.text().strip()
        resultado = ''

        try:
            if cifra == "César":
                chave_int = int(chave)
                resultado = cifra_cesar(texto, chave_int, modo)

            elif cifra == "Atbash":
                resultado = cifra_atbash(texto)

            elif cifra == "Numérica (A1Z26)":
                resultado = cifra_numerica(texto, modo)

            elif cifra == "Vigenère":
                if not chave.isalpha():
                    self.mostrar_erro(
                        "Chave inválida. Use apenas letras na cifra de Vigenère.")
                    return
                resultado = cifra_vigenere(texto, chave, modo)

            else:
                resultado = "Cifra não implementada."

        except ValueError:
            self.mostrar_erro("Chave inválida. Informe um valor apropriado.")
            return

        self.result_output.setPlainText(resultado)

# === Execução ===


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CifraApp()
    window.show()
    sys.exit(app.exec_())
