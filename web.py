from flask import Flask, jsonify, send_file, request, Response
import json
import os

app = Flask(__name__)


def carregar_json(nome_arquivo: str) -> dict:
    """
    Carrega o conteúdo de um arquivo JSON.

    Args: nome_arquivo (str): O caminho do arquivo JSON a ser carregado.

    Returns:
        dict: O conteúdo do arquivo JSON como um dicionário. Retorna um dicionário vazio se o arquivo não existir ou estiver corrompido.
    """
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


def salvar_json(usuarios: dict[str, dict[str, str | int]]) -> None:
    """
    Salva os dados dos usuários em um arquivo JSON.

    Args:
        usuarios (dict[str, dict[str, str | int]]): Dicionário que armazena os usuários cadastrados.
    """
    with open("usuario.json", 'w') as usuario:
        usuario.write(json.dumps(usuarios, indent=2))


@app.route('/')
def home() -> tuple[Response, int] | Response:
    """
    Rota principal que retorna o conteúdo do arquivo 'usuario.json' como JSON.

    Returns:
        flask. Response: Uma resposta JSON contendo os dados do arquivo 'usuario.json' ou uma mensagem de erro.
    """
    usuario = carregar_json('usuario.json')
    if usuario is None:
        try:
            return jsonify({"error": "Arquivo JSON está vazio."}), 200
        except json.JSONDecodeError:
            return jsonify({"error": "Arquivo JSON não encontrado ou corrompido."}), 400
    return jsonify(usuario)


@app.route('/', methods=['POST'])
def home_post() -> tuple[Response, int]:
    """
    Rota para lidar com requisições POST. Recebe dados JSON e retorna uma resposta com os dados recebidos.

    Returns:
        flask. Response: Uma resposta JSON contendo uma mensagem de sucesso e os dados recebidos.
    """
    # Obtendo os dados enviados na requisição POST
    data = request.get_json()

    salvar_json(data)
    # Exemplo de manipulação dos dados recebidos
    nome = data.get('nome', 'Sem nome')
    email = data.get('email', 'Sem email')
    print(json.dumps(data, indent=2))

    # Retorna uma resposta com os dados recebidos
    return jsonify(data), 200


@app.route('/baixar')
def baixar() -> Response:
    """
    Rota para baixar o arquivo 'usuario.json'.

    Returns:
        flask.Response: Uma resposta que permite o download do arquivo 'usuario.json'.
    """
    return send_file('usuario.json', as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
