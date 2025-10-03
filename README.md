# Assinador Digital:

# Pré-requisitos e Build do Projeto:

- Java 17 (17.0.16)
- Maven 3.9.10
- (Opcional) IntelliJ (Ou outra IDE, para esse passo a passo estaremos utilizando os runners pela IDE)

Recomendo para a utilização de mais de uma versão java o SDKMan que permite que existam vários candidates para a versão atual do Java e do Maven, entre outras linguagens/gerenciadores semelhantes.

### Clone o repositório do projeto 

`git clone https://github.com/arthurwinck/assinador-digital`

Builde e instale o projeto com:

`mvn clean install -U`

Crie um runner dentro de Run/Debug Configurations com as seguintes propriedades (Caso não utilize alguma IDE, rode `mvn spring-boot:run` passando as variáveis necessárias(portas, variáveis de ambiente, e outros):

<img width="805" height="393" alt="Screenshot From 2025-09-16 07-09-29" src="https://github.com/user-attachments/assets/4d2374c8-cf71-401e-b296-60aea763c931" />

Inicialize o runner pelo Debug (ou Runner) com F5 para Debug e Ctrl + F5 pra Run

A API estará disponível no root path (caminho raíz). Requisições são feitas para a porta 8080 por padrão. Ex: localhost:8080/verify

Para a execução dos testes de integração, é necessário alterar o runner padrão do teste do JUnit para que seja possível utilizar a senha da chave privada e também o certificado:

Senha presente na variável de ambiente KEY_PASSWORD para testes de integração SigningServiceIntegrationTest e VerifyServiceIntegrationTest.

Nome do certificado presente na variável de ambiente TEST_CERTIFICATE_NAME. Nome padrão do artefato é: “certificado_teste_hub”

<img width="805" height="393" alt="Screenshot From 2025-09-16 09-07-19" src="https://github.com/user-attachments/assets/ddab1e30-3c12-4fe9-b74f-8af4405859d0" />


Além disso, é necessário disponibilizar o arquivo .pfx no path src/test/resources/keys. Dessa forma é possível executar os dois testes de integração que utilizam o certificado e a chave privada.


# Desenvolvimento:

A estrutura desenvolvida é a seguinte: Resources são os arquivos responsáveis por gerenciar as requisições e os Services os arquivos responsáveis pela lógica de negócio: realizar a assinatura/verificação de assinatura e devolvê-la para o usuário.

De início para facilitar o teste das funcionalidades, foram criados 3 resources, o HashResource, SigningResource e VerifyResource. O desenvolvimento do HashService demonstrou-se bem simples, sendo sua funcionalidade somente retornar o hash SHA512 de uma string ou de um arquivo (em /hash/upload). Os dois outros services foram mais desafiadores, sendo necessário ler a documentação do BouncyCastle, e outros sites de ajuda por conta de nunca ter utilizado a biblioteca. Porém, ela é robusta e possui muita documentação sobre seus métodos e como utilizá-los. 

Outra dificuldade foi na declaração do tipo do arquivo da assinatura salva, algumas horas foram gastas “debuggando” o motivo pelo qual o arquivo .p7 não podia ser lido corretamente nas validações. Somente após esse tempo ajustei para que os arquivos sempre fossem salvos no formato correto, .p7m, indicando a presença do conteúdo assinado dentro da assinatura.

Os testes unitários se mostraram um desafio, pois seria necessário realizar o “mock” de todos os retornos das classes e métodos da biblioteca BouncyCastle. Para conseguir realizar um teste mais completo sem que seja necessário “mockar” muitos retornos de métodos de bibliotecas, foram criados dois arquivos de teste, o VerifyServiceIntegrationTest e o SigningServiceIntegrationTest.

Testes unitários relacionados aos métodos auxiliares, e autenticação para uso são algumas das melhorias que gostaria de implementar caso possuísse mais tempo. Outro fator seria mudar a maneira que realizamos a assinatura pois estamos enviando a senha de uma privada para o servidor, de forma que qualquer atacante que pudesse interceptar a mensagem poderia roubar a chave privada daquele usuário.

Por fim, outro ponto de melhoria do código é a implementação de mensagens de validação mais específicas. Erros de senha, ou de arquivos inutilizáveis retornam o mesmo erro de servidor e não indicam ao usuário exatamente qual foi o problema para que uma assinatura não tenha dado certo.

# Validação


## Assinatura

CURL realizado para assinatura do arquivo doc.txt:

`curl -X POST http://localhost:8080/signature -F "file=@./src/main/resources/files/doc.txt" -F "pkcs12=@./src/main/resources/keys/certificado_teste_hub.pfx" -H "X-password: *********"`

O arquivo gerado é salvo com o timestamp do momento em que foi gerado.

Para validar o resultado, também foi utilizado o ASN.1 JavaScript decoder. Nele podemos ver as informações sobre o certificado digital que foi utilizado para a assinatura do documento

<img width="818" height="684" alt="Screenshot From 2025-09-16 06-52-06" src="https://github.com/user-attachments/assets/de85a350-96e6-426c-ace6-bb0c6ab137cb" />

Exemplo de assinaturas geradas:

<img width="185" height="181" alt="Screenshot From 2025-09-16 06-58-26" src="https://github.com/user-attachments/assets/490c328d-0762-44b0-b463-ac10d9f79043" />


Testes de integração foram realizados para que fosse possível verificar que o fluxo de assinatura funciona corretamente com strings. 

Verificação

CURL realizado utilizando o arquivo “20250916131959.p7m” que acabou de ser gerado pelo passo anterior:

`http://localhost:8080/verify -F "file=@./20250916131959.p7m"`

Resultado:

<img width="1306" height="187" alt="image" src="https://github.com/user-attachments/assets/2b8eb8c7-e528-461b-9d8b-7b88768354de" />

Alternativamente, em texto:

```json
{
    "originalData": "54657374652076616761206261636b2d656e64204a617661",
    "status": "VALIDO",
    "signinTimeDate": "Tue Sep 16 13:19:59 GMT-03:00 2025",
    "encapContentInfoHash": "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35",
    "digestAlgorithm": "SHA512",
    "cnsignerName": "CN=HUB2 TESTES,OU=Validado por email,O=BRy Tecnologia,C=BR,ST=SC,L=Florianopolis,E=darlan@bry.com.br,"
}
```

Como teste de controle, foi feita também a validação por meio do site CMS Validator, tendo como resultado:


<img width="1370" height="616" alt="Screenshot From 2025-09-15 18-03-55" src="https://github.com/user-attachments/assets/1f2d8d70-0d5d-4272-aed2-66e179ed8cf0" />


# Distribuição de Código:

Para conseguirmos executar os testes de integração que foram implementados anteriormente, tivemos que fazer algumas alterações para que os testes busquem o certificado por meio de um resource no classpath (estando disponível na pasta resources). Porém, não podemos commitar tais arquivos, e para isso, criamos secrets (ou variáveis de ambiente “escondidas”) para a codificação Base64 do arquivo do certificado, para o nome do certificado codificado e também para a senha da chave privada que o acompanha.

<img width="1357" height="413" alt="Screenshot From 2025-09-16 09-19-41" src="https://github.com/user-attachments/assets/9f37102e-4859-41b6-8a2e-9f66a85ac939" />

Nessa situação, utilizamos os secrets de repositório, porém como melhoria, seria interessante criar as variáveis por ambiente, podendo ter variáveis específicas para ambientes de desenvolvimento e produção.

Outro ponto é o disparo desses workflows a partir da criação de uma tag, pois atualmente qualquer commit na main dispara os dois fluxos.

Com isso é possível ver o resultado dos testes na etapa “Run Tests” e “Build and Release JAR“ do workflow do repositório:


<img width="1237" height="267" alt="Screenshot From 2025-09-16 09-21-56" src="https://github.com/user-attachments/assets/5e8b36eb-4eb6-4bbe-ab82-d55788031717" />

Exemplo de execução dos testes dentro do workflow:

<img width="1248" height="576" alt="Screenshot From 2025-09-16 09-24-03" src="https://github.com/user-attachments/assets/83eae2be-cb9e-40b1-992e-307b9e43fee6" />

Disponibilização das releases .JAR criadas pelo workflow de releases:

<img width="1403" height="1050" alt="Screenshot From 2025-09-16 09-25-03" src="https://github.com/user-attachments/assets/e43bfa45-11e0-4bc4-9e33-7baf4ebc578a" />

# Tratamento de erros e exceções

Exceções customizadas foram criadas para mapear situações específicas de erros. A seguir temos as definições de cada exceção. A exceção retornada ao Resource será sempre uma SigningValidationException ou uma VerifyValidationException para o serviço de assinatura e o serviço de verificação, respectivamente. Erros não mapeados serão transformados em GenericException. Qualquer erro não mapeado retorna um status de 500, erro de servidor.s

### SigningValidationException
Exceção base disparada sempre que o serviço encontra um erro ao tentar realizar uma assinatura.

### InvalidCertificateException (400 - Bad Request)
Disparada sempre que não seja possível recuperar a chave privada a partir do arquivo enviado.

### CMSException (Nativa BC) (500 - Server Error)
Exceção nativa da biblioteca que ocorre quando não é possível adicionar certificados ao gerador de assinatura.

### OperatorCreationException (Nativa BC) (500 - Server Error)
Disparada quando não é possível instanciar estruturas necessárias para realizar assinatura
CertificateException (Nativa BC) (400 -  Bad Request)
Disparada em uma variedade de erros relacionados ao certificado.

### KeyStoreException (Nativa Java Security) (500 - Server Error)
Disparada quando keyStore não foi inicializado corretamente (erro ao tentar instanciar keystore a partir do arquivo enviado).

### UnrecoverableKeyException (Nativa Java Security) (400 - Bad Request)
Disparada quando a senha do keyStore está incorreta

### VerifyValidationException
Exceção base disparada quando o serviço de verificação de assinaturas encontra um erro. 

### InvalidSignedContentException (400 - Bad Request)
Disparada quando conteúdo assinado não está presente no arquivo. Assinatura do tipo “detached” não funcionará pois o conteúdo original precisa estar anexado ao arquivo.

### InvalidSignatureFileException (400 - Bad Request)
Disparada quando não é possível instanciar o objeto de assinatura com conteúdo anexado a partir do arquivo de entrada ou quando algum dos certificados não se encontra na estrutura necessária.

# Referências:

https://stackoverflow.com/questions/27917846/explore-a-bouncy-castle-store-object
https://javadoc.io/doc/org.bouncycastle/bcpkix-jdk15to18/latest/index.html
https://stackoverflow.com/questions/35099408/generate-a-cms-pkcs7-file-with-bouncycastle-in-c-sharp
https://downloads.bouncycastle.org/java/docs/bcpkix-jdk13-javadoc/org/bouncycastle/cms/SignerInformationVerifier.html

