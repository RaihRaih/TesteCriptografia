from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class CriptografiaDados:
    @staticmethod
    def criptografar_aes(nome, curso, mensagem):
        try:
            # Gera uma chave e um vetor de inicialização (IV) aleatórios para AES
            key = os.urandom(32)  # 256 bits
            iv = os.urandom(16)   # 128 bits

            # Cria o texto completo com as informações fornecidas
            texto = f"Nome: {nome}\nCurso: {curso}\nMensagem: {mensagem}"

            # Chama a função de criptografia
            criptografado = CriptografiaDados.criptografar(texto, key, iv)
            print(f"\nDados Criptografados: {criptografado}")

            # Chama a função de descriptografia para verificar o texto original
            descriptografado = CriptografiaDados.descriptografar(criptografado, key, iv)
            print(f"\nDados Descriptografados: {descriptografado}")
        except Exception as e:
            print(f"Erro: {e}")
        print("\nAção executada com sucesso!")

    @staticmethod
    def criptografar(plain_text, key, iv):
        # Padding para garantir que o texto seja múltiplo de 16 bytes
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()

        # Configuração do cipher AES
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        criptografado = encryptor.update(padded_data) + encryptor.finalize()
        return criptografado

    @staticmethod
    def descriptografar(cipher_text, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(cipher_text) + decryptor.finalize()

        # Remove o padding após descriptografia
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted_data.decode()

# Executa o programa
while True:
    # Solicita os dados do usuário
    nome = input("Insira seu nome: ")
    curso = input("Insira seu curso: ")
    mensagem = input("Insira a mensagem a ser criptografada: ")
    
    # Chama a função de criptografia com os dados inseridos
    CriptografiaDados.criptografar_aes(nome, curso, mensagem)

    # Condição de saída
    letra = input("\n\tAperte a tecla 'q' + 'Enter' para sair do programa.\n\tSe deseja continuar, aperte 'Enter'.\n").lower()
    if letra == 'q':
        break

print("\nAté breve!")
