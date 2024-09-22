import json
import os
import hashlib

id_apagado = []


def menu() -> None:
    """
    Exibe o menu de opções para o sistema de cadastro de usuários.

    Esta função imprime as opções disponíveis no sistema de cadastro de usuários.
    O usuário pode escolher entre cadastrar, buscar, deletar, listar, atualizar usuários ou sair do sistema.
    """
    op = ['Cadastrar Usuário', 'Buscar Usuário', 'Deletar Usuário', 'Listar Usuários', 'Atualizar Usuários', 'Sair']
    for index, alternativa in enumerate(op):
        print(f"{index + 1}. {alternativa}")


def cadastrar_usuario(usuarios: dict[str, dict[str, str | int]]) -> dict[str, dict[str, str | int]]:
    """
    Cadastra um novo usuário no sistema.

    Args: usuarios (dict[str, dict[str, str | int]]): Dicionário que armazena os usuários cadastrados.

    Returns:
        dict[str, dict[str, str | int]]: dicionário atualizado com o novo usuário.
    """
    nome: str = obter_nome_usuario()  # Obtém o nome do usuário
    idade: int = validar_idade()  # Valida a idade do usuário
    email: str = verificar_email()  # Verifica se o e-mail é válido
    senha: str = obter_senha_usuario()  # Obtém a senha do usuário
    passw: int
    salt: bytes
    passw, salt = hash_senha(senha)  # Gera o hash e salt da senha
    user_id = id_apagado.pop(0) if id_apagado else calcular_id(usuarios)  # Usa o primeiro ID apagado, se houver
    usuarios[str(user_id)] = {
        'nome': nome,
        'idade': idade,
        'email': email,
        'senha': senha,
        'hash': passw,
        'salt': str(salt)
    }

    print("Usuário cadastrado com sucesso!")
    return usuarios


def buscar_usuario(usuarios: dict[str, dict[str, str | int]]) -> None:
    """
    Busca um usuário pelo nome e, se necessário, pelo e-mail, e exibe suas informações.

    Args:
        usuarios (dict[str, dict[str, str | int]]): Dicionário que armazena os usuários cadastrados.
    """
    nome: str = obter_nome_usuario()  # Obtém o nome do usuário
    usuarios_encontrados = [user_id for user_id, info in usuarios.items() if info['nome'].lower() == nome.lower()]

    if not usuarios_encontrados:
        print("Usuário não encontrado!")
        return

    if len(usuarios_encontrados) > 1:
        # Se houver mais de um usuário com o mesmo nome, solicitar o e-mail
        email = verificar_email()
        usuarios_encontrados = [user_id for user_id in usuarios_encontrados if
                                usuarios[user_id]['email'].lower() == email.lower()]

    if len(usuarios_encontrados) == 1:
        usuario_id = usuarios_encontrados[0]
        info = usuarios[usuario_id]
        print(f'O usuário {info["nome"]} tem {info["idade"]} anos e o email dele é {info["email"]}')
    else:
        print("Usuário não encontrado ou múltiplos usuários com esse nome e e-mail.")


def deletar_usuario(usuarios: dict[str, dict[str, str | int]]) -> None:
    """
    Remove um usuário do sistema pelo nome.

    Args:
        usuarios (dict[str, dict[str, str | int]]): Dicionário que armazena os usuários cadastrados.
    """
    nome: str = obter_nome_usuario()  # Obtém o nome do usuário
    usuarios_encontrados = [user_id for user_id, info in usuarios.items() if info['nome'].lower() == nome.lower()]

    if not usuarios_encontrados:
        print("Usuário não encontrado!")
        return

    if len(usuarios_encontrados) > 1:
        # Se houver mais de um usuário com o mesmo nome, solicitar o e-mail
        email = verificar_email()
        usuarios_encontrados = [user_id for user_id in usuarios_encontrados if
                                usuarios[user_id]['email'].lower() == email.lower()]

    if len(usuarios_encontrados) == 1:
        usuario_id = usuarios_encontrados[0]
        info = usuarios[usuario_id]
        id_apagado.append(usuario_id)

        # Verifica a senha antes de deletar
        if verificar_senha(usuario_id, usuarios):
            print(f"O usuário {info['nome']}, que tem {info['idade']} anos e email {info['email']}, será deletado.")
            del usuarios[usuario_id]  # Deleta o usuário
            print("Usuário deletado com sucesso.")
        else:
            print("Senha incorreta! Não foi possível deletar o usuário.")
    else:
        print("Usuário não encontrado ou múltiplos usuários com esse nome e e-mail.")


def listar_usuarios(usuarios: dict[str, dict[str, str | int]]) -> None:
    """
    Lista todos os usuários cadastrados e suas informações.

    Args:
        usuarios (dict[str, dict[str, str | int]]): Dicionário que armazena os usuários cadastrados.
    """
    if not usuarios:  # Verifica se não há usuários cadastrados
        print("Nenhum usuário cadastrado!!")
        return
    for user_id, info in usuarios.items():  # Lista todos os usuários
        print(f"O usuário {info['nome']} tem {info['idade']} anos e o email é {info['email']}")


def atualizar_usuario(usuarios: dict[str, dict[str, str | int]]) -> None:
    """
    Atualiza as informações de um usuário no sistema.

    Args:
        usuarios (dict[str, dict[str, str | int]]): Dicionário que armazena os usuários cadastrados.
    """
    info = ''
    usuario_id = ''
    nome = obter_nome_usuario()  # Obtém o nome do usuário
    usuarios_encontrados = [user_id for user_id, info in usuarios.items() if info['nome'].lower() == nome.lower()]

    if not usuarios_encontrados:
        print("Usuário não encontrado!")
        return

    if len(usuarios_encontrados) > 1:
        # Se houver mais de um usuário com o mesmo nome, solicitar o e-mail
        email = verificar_email()
        usuarios_encontrados = [user_id for user_id in usuarios_encontrados if
                                usuarios[user_id]['email'].lower() == email.lower()]

    if len(usuarios_encontrados) == 1:
        usuario_id = usuarios_encontrados[0]
        info = usuarios[usuario_id]
    if not verificar_senha(usuario_id, usuarios):  # Verifica se o usuário existe e a senha está
        # correta
        print("Usuário não encontrado ou senha incorreta!")
        return

    while True:
        tipo = int(input("Digite o tipo de atualização:\n"
                         "1 para nome\n"
                         "2 para idade\n"
                         "3 para e-mail\n"
                         "4 para senha\n"
                         "5 para parar a atualização\n"
                         "Digite: "))
        match tipo:
            case 1:
                info['nome'] = obter_nome_usuario()  # Atualiza o nome
            case 2:
                info['idade'] = validar_idade()  # Atualiza a idade
            case 3:
                info['email'] = verificar_email()  # Atualiza o e-mail
            case 4:
                senha = obter_senha_usuario()  # Obtém a nova senha
                info['senha'] = senha
                password, salt = hash_senha(senha)  # Gera o hash e salt da nova senha
                info['hash'] = password
                info['salt'] = str(salt)
            case 5:
                print("Atualização encerrada.")
                break
            case _:
                print("Informe uma opção válida!!")

        continua = int(input("Deseja atualizar outro dado?\n"
                             "1 para sim\n"
                             "2 para não\n"
                             "Digite: "))
        if continua == 2:  # Verifica se o usuário deseja parar a atualização
            print("Dados atualizados com sucesso!")
            break


def verificar_email() -> str:
    """
    Solicita um e-mail e verifica se é válido.

    Returns:
        str: O e-mail válido informado pelo usuário.
    """
    while True:
        email = input("Informe o email do usuário: ").strip().lower()  # Obtém o e-mail e formata
        if '@' in email and '.' in email and '.' not in email[0] and '.' not in email[-1] and verificar_caracteres(
                email) and len(email) <= 320:  # Verifica se o e-mail é válido
            return email
        print("Informe um email válido!")


def obter_senha_usuario() -> str:
    """
    Solicita a senha do usuário e valida se é válida.

    Returns:
        str: senha do usuário.
    """
    while True:
        password = input("Digite sua senha: ").strip()  # Obtém a senha do usuário
        if verificar_caracteres(password):  # Verifica se a senha é válida
            return password
        print("Informe uma senha válida!")


def hash_senha(password: str, salt: bytes = None) -> tuple[int, bytes]:
    """
    Gera um hash para a senha usando o algoritmo SHA-256.

    Args: password (str): A senha a ser criptografada.
    Args: salt (bytes, opcional): Salt utilizado no hash. Se não fornecido, será gerado.

    Returns:
        tuple: Hash da senha e o salt utilizado.
    """
    if salt is None:
        salt = os.urandom(16)  # Gera um salt aleatório se não for fornecido
    texto_hash = password + str(salt)  # Combina a senha e o salt
    sha_signature = int(hashlib.sha256(texto_hash.encode()).hexdigest(), 16)  # Gera o hash
    return sha_signature, salt


def verificar_senha(user_id: str, usuarios: dict[str, dict[str, str | int]]) -> bool:
    """
    Verifica se a senha fornecida é válida para o usuário.

    Args: nome (str): Nome do usuário.
    Args: usuarios (dict[str, dict[str, str | int]]): Dicionário com as informações dos usuários.

    Returns:
        bool: True se a senha for válida, false caso contrário.
    """
    try:
        password = obter_senha_usuario()  # Obtém a senha fornecida pelo usuário
        password_hash, _ = hash_senha(password, usuarios[user_id]['salt'])  # Gera o hash usando o salt do
        # usuário
        return password_hash == usuarios[user_id]['hash']  # Verifica se o hash corresponde
    except KeyError:
        print("Usuário não encontrado!")
        return False


def verificar_caracteres(texto: str) -> bool:
    """
    Verifica se o texto contém caracteres especiais proibidos.

    Args: texto (str): Texto a ser verificado.

    Returns:
        bool: Retorna True se o texto não contiver caracteres inválidos.
    """
    char = [' ', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '[', ']', '{', '}', '|', '\\', ':', ';',
            '"', "'", '<', '>', '?', '-']  # Caracteres proibidos
    return not any(caracter in texto for caracter in char)  # Retorna True se não encontrar caracteres proibidos


def validar_idade() -> int:
    """
    Solicita e valida a idade do usuário.

    Returns:
        int: idade válida do usuário.
    """
    while True:
        try:
            idade = int(input("Informe a idade do usuário: ").strip())  # Obtém a idade e tenta converter para int
            if 0 <= idade <= 120:  # Verifica se a idade está dentro dos limites
                return idade
            else:
                print("A idade deve estar entre 0 e 120 anos. Tente novamente.")
        except ValueError:
            print("Entrada inválida. Por favor, informe um número inteiro.")  # Trata entradas inválidas


def obter_nome_usuario() -> str:
    """
    Solicita e retorna o nome do usuário formatado.

    Returns:
        str: nome do usuário com a primeira letra maiúscula.
    """
    return input("Digite o nome do usuário: ").strip().capitalize()  # Obtém e formata o nome


def validar_opcao_menu() -> int:
    """
    Valida a opção informada no menu principal.

    Returns:
        int: A opção válida do menu.
    """
    while True:
        try:
            alternativa = int(input("Informe a opção que deseja: "))  # Obtém a opção do usuário
            if 1 <= alternativa <= 6:  # Verifica se a opção está dentro do intervalo
                return alternativa
            print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Informe um número válido.")  # Trata entradas inválidas


def calcular_id(usuario: dict) -> int:
    if len(usuario) >= 1:
        return max(int(usuario) for usuario in usuarios.keys()) + 1
    else:
        return 1


def salvar_json(usuarios: dict) -> None:
    with open("usuario.json", 'w') as usuario:
        usuario.write(json.dumps(usuarios, indent=2))


def carregar_json(nome_arquivo: str) -> dict:
    # Verifica se o arquivo existe
    if os.path.exists(nome_arquivo):
        with open(nome_arquivo, 'r') as arquivo:
            try:
                # Carrega e retorna o conteúdo do arquivo JSON
                return json.load(arquivo)
            except json.JSONDecodeError:
                print("Erro ao decodificar o JSON. O arquivo pode estar corrompido.")
                return {}
    else:
        print(f"O arquivo {nome_arquivo} não existe.")
        return {}


arquivo_json = 'usuario.json'

usuarios = carregar_json(arquivo_json)  # Dicionário para armazenar os usuários

while True:
    menu()  # Exibe o menu
    opcao = validar_opcao_menu()  # Obtém a opção do menu

    match opcao:
        case 1:
            usuarios = cadastrar_usuario(usuarios)  # Cadastra um usuário
            salvar_json(usuarios)
        case 2:
            buscar_usuario(usuarios)  # Busca um usuário
        case 3:
            deletar_usuario(usuarios)  # Deleta um usuário
            salvar_json(usuarios)
        case 4:
            listar_usuarios(usuarios)  # Lista todos os usuários
        case 5:
            atualizar_usuario(usuarios)  # Atualiza informações de um usuário
            salvar_json(usuarios)
        case 6:
            print("Saindo....")  # Mensagem de saída
            break  # Encerra o loop
