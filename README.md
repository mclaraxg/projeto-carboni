# Autenticação segura com Flask

Aplicação web simples para cadastro e login com foco em segurança de senhas.

## Requisitos atendidos

- Cadastro de usuários com nome, e-mail e senha.
- Senhas armazenadas com hash criptográfico e salt único por usuário.
- Login com verificação segura das credenciais.
- Política mínima de senha.
- Limite de tentativas com bloqueio temporário.
- Registro de logs.
- Validação de força de senha.

## Como executar

```powershell
pip install -r requirements.txt
python app.py
```

Abra `http://127.0.0.1:5000` no navegador.

## Estrutura

- `app.py`: aplicação Flask, rotas e persistência SQLite.
- `security.py`: hash, salt, verificação e política de senha.
- `templates/`: páginas HTML.
- `auth.db`: banco SQLite gerado automaticamente.
- `auth.log`: logs de autenticação.

## Observação acadêmica

Esta implementação foi pensada para demonstração didática. Ela não substitui uma arquitetura de produção com gestão formal de segredos, monitoramento centralizado e endurecimento adicional de sessão, CSRF e rate limiting por IP.