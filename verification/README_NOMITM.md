

1. Le Lemme secrecy_Kab_PFS

Ce lemme vise à vérifier la propriété de Perfect Forward Secrecy (PFS) pour la clé de session Kab.

Voici la lecture de la trace fournie :

    solve( Secret( A, B, k ) @ #i ) : Tamarin cherche un état où A déclare que la clé k est secrète.

        case Init_2 : Il trouve que c'est la règle Init_2 (l'étape 3 du protocole) qui génère cet événement Secret.

    solve( St_A_1( $A, $B, ~na ) ▶₀ #i ) : Pour que Init_2 se produise, il faut que l'état précédent St_A_1 existe.

        case Init_1 : Cet état est créé par la règle Init_1 (étape 1 du protocole).

    solve( !Ltk( $A, ~ltkA ) ▶₂ #i ) : Pour Init_2, A a besoin de sa clé privée pour déchiffrer le message reçu.

        case Register_pk : La clé privée vient de l'enregistrement initial.

    solve( !Pk( $B, pkB ) ▶₃ #i ) : A a besoin de la clé publique de B pour chiffrer le message suivant.

        case Register_pk : La clé publique vient de l'enregistrement initial.

    solve( !KU( ~kab ) @ #vk ) : Tamarin suppose (pour trouver une attaque) que l'attaquant connaît la clé ~kab (!KU signifie Knowledge of adversary). Il cherche comment l'attaquant a pu l'apprendre.

        case Init_2_case_1 : L'attaquant apprend ~kab en déchiffrant le message envoyé par A à l'étape 3 ({Kab, Nb, Na, A}pk(B)). Pour cela, il a besoin de la clé privée de B (~ltkB ou ~ltkX dans la trace générique).

    solve( !KU( ~ltkX ) @ #vk.2 ) : Comment l'attaquant a-t-il eu la clé privée de B (~ltkX) ?

        case Reveal_ltk : L'attaquant l'a obtenue via la règle Reveal_ltk (compromission explicite).

    solve( !KU( aenc(<$B, nb, ~na>, pk(~ltkA)) ) @ #vk.2 ) : Tamarin remonte encore le temps. Pour que A arrive à l'étape 3 (Init_2) et envoie Kab, il faut qu'il ait reçu le message de l'étape 2 ({B, Nb, Na}pk(A)). L'attaquant doit donc être capable de construire ou relayer ce message.

        case Resp_1 : Le message a été honnêtement généré par B à l'étape 2.

    SOLVED // trace found

    Comme Kab a été envoyée chiffrée avec la clé publique de B (dans le message 3), l'attaquant peut utiliser la clé privée volée pour déchiffrer ce message enregistré (qu'il a écouté sur le réseau) et récupérer Kab

    Mais c'est autorisé par l'énoncé et cela ne compromet pas les futurs ou actuelles communications donc l'attaque n'est pas valide. Car Tamarin s'autorise à remonter dans le temps donc il doit forcement jouer avec les anciennes sessions car il revele une ancienne clé privé.

    Attaque non valide.



2. Le Lemme aliveness_A_authenticates_B

La propriété dit : si je pense parler à quelqu'un, cette personne doit au moins avoir fait quelque chose (être "vivante").

Tamarin a trouvé une séquence d'événements où A termine sa session avec B, mais B n'a jamais rien fait pour cette session.

La trace :

    solve( St_A_1( $A, $B, ~na ) ▶₀ #i ) et case Init_1 :

        L'agent A (identifié par $A) commence une session pour parler à B (identifié par $B).

        Il envoie le message 1 : A, Na.

    solve( !KU( aenc(<$B, nb, ~na>, pk(~ltkA)) ) @ #vk ) :

        Pour que A continue à l'étape 3 (Init_2), il doit recevoir le message 2 : {B, Nb, Na}pk(A).

        Tamarin cherche comment l'attaquant (!KU) a pu construire ce message.

    case c_aenc :

        L'attaquant a construit ce message lui-même en utilisant la fonction de chiffrement asymétrique aenc.

        Pour faire ça, l'attaquant a besoin de trois choses :

            L'identité $B (publique).

            Un nonce nb (l'attaquant peut en inventer un ou en réutiliser un).

            Le nonce ~na (envoyé par A à l'étape 1).

            La clé publique de A (pk(~ltkA)).

    solve( !KU( ~na ) @ #vk.6 ) et case Init_1 :

        L'attaquant a récupéré ~na simplement en écoutant le message 1 envoyé par A (qui est en clair : A, Na).

    solve( !KU( pk(~ltkA) ) @ #vk.3 ) et case Register_pk :

        L'attaquant connaît la clé publique de A (elle est publique).

    SOLVED // trace found :

Pour resumer : 

    A -> Attaquant (se faisant passer pour B) : A, Na

        A envoie son défi Na à B. L'attaquant intercepte ce message.

    Attaquant -> A : {B, Nb_attaquant, Na}pk(A)

        L'attaquant forge un message de réponse. Il prend le Na qu'il vient de voir, invente son propre nonce Nb_attaquant, et chiffre le tout avec la clé publique de A.

        Il n'a pas besoin de la clé privée de B pour faire ça ! N'importe qui peut chiffrer avec la clé publique de A.

    A -> Attaquant : {Kab, Nb_attaquant, Na, A}pk(B)

        A déchiffre le message 2, voit son Na et pense que B a répondu.

        A termine sa session (Commit_I), génère une clé Kab et l'envoie chiffrée pour B.

Résultat : A a fini sa session et pense avoir parlé à B. Sauf que A ne reçoit jamais le hash finale donc ne valide pas le protocole donc attaque non valide.


3. Le Lemme agreement_A_authenticates_B

Ce lemme vise à prouver la propriété de Weak Agreement (Accord Faible) ou Non-injective Agreement.

En termes simples : "Si A termine une session (Commit_I) en pensant parler à B avec le nonce n (Na), alors B doit avoir lancé une session (Running_R) pour parler à A avec ce même nonce n, SAUF si l'une des clés privées a été compromise (Reveal)."

C'est une propriété plus forte que l'Aliveness. Elle exige non seulement que B soit actif, mais qu'il soit d'accord sur qui il parle (A) et sur certaines données (n).

L'attaque trouvée par Tamarin est essentiellement la même que pour l'Aliveness (Man-in-the-Middle sur l'authentification initiale), mais vue sous l'angle de l'accord.

La trace :

    solve( St_A_1( $A, $B, ~na ) ▶₀ #i ) / case Init_1 :

        A initie une session vers B avec le nonce ~na.

    solve( !KU( aenc(<$B, nb, ~na>, pk(~ltkA)) ) @ #vk ) :

        A attend le message 2 : {B, Nb, Na}pk(A).

        L'attaquant doit fournir ce message pour que A continue et fasse son Commit.

    case c_aenc :

        L'attaquant forge ce message lui-même !

        Il utilise pk(A) (publique), l'identité de B (publique), le nonce ~na (qu'il a vu passer en clair à l'étape 1), et un nonce nb de son choix.

    SOLVED // trace found :

        L'attaque est réussie. A reçoit le faux message, croit qu'il vient de B (car il contient ~na), et termine sa session (Commit).

        Cependant, B n'a jamais exécuté Running_R avec A et ~na.

        Donc, la condition "Exists Running_R..." est fausse, et aucune clé n'a été révélée. Le lemme est falsifié.

Pour résumer :

    Ce que A croit : "J'ai parlé à B, il a vu mon nonce Na, et nous sommes d'accord pour continuer."

    La réalité : A a parlé à l'attaquant. B n'est même pas au courant qu'une session existe. L'attaquant a simplement ré-encapsulé le nonce de A dans un message chiffré pour A.

Mais ce n'est pas un problème car le protocole assure par la suite que A verifiera qu'il a communiquer avec B et que B était bien vivant. L'attaque est donc non valide.

SOLVED // trace found signifie encore une fois que Tamarin a trouvé une attaque contre le lemme injective_agreement_A_authenticates_B.

4. Le Lemme injective_agreement_A_authenticates_B

Ce lemme est la propriété d'authentification la plus forte pour ce contexte. Elle impose deux conditions :

    Accord (Agreement) : Si A termine (Commit_I) avec le nonce n, alors B doit avoir lancé une session (Running_R) avec ce même n.

    Injectivité (Unicité) : Il doit y avoir une relation 1 pour 1. Pour chaque Commit de A, il doit y avoir une exécution unique de B. A ne doit pas accepter deux fois le même message de B (protection contre le rejeu).

La trace générée par Tamarin montre ici que la première condition (l'accord de base) est déjà violée.

vaeenma/Indiapicture

    case Init_1 : A démarre une session et envoie Na.

    case c_aenc : L'attaquant forge le message 2 {B, Nb_fake, Na}pk(A).

        Comme vu précédemment, le message 2 n'est pas authentifié. L'attaquant peut le créer en utilisant la clé publique de A et le Na qu'il a écouté.

    SOLVED : A reçoit ce faux message, croit qu'il vient de B, et termine sa session (Commit_I).

Pourquoi cela brise l'Accord Injectif ?

L'accord injectif nécessite que B ait exécuté Running_R. Or, dans cette trace :

    A a fait Commit_I.

    B n'a jamais fait Running_R (c'est l'attaquant qui a répondu).

Comme la condition de base "B a participé" est fausse, la condition "B a participé une seule fois" n'a même pas besoin d'être testée. L'attaque est un Man-in-the-Middle (MITM) sur l'identité de B.

Le protocole échoue à garantir l'Accord Injectif car il échoue déjà à garantir l'Accord Faible. L'absence d'authentification de l'expéditeur dans le message 2 {B, Nb, Na}pk(A) permet à un attaquant de se faire passer pour B dès le début, pour autant ce sera verifié à la fin donc les specifications ainsi que le sujet ne permettent pas de dire que cette attaque est valide.

5. injective_agreement_B_authenticates_A indique une attaque par violation de l'accord injectif.

Cela signifie que, bien que B pense communiquer avec A en respectant les termes du protocole, l'accord unique attendu n'est pas garanti. Plus précisément, cela peut être une attaque de type Man-in-the-Middle (MITM) où l'attaquant parvient à faire croire à B qu'il est en train de compléter une session avec A, alors que A n'a pas initié cette session avec les paramètres attendus ou qu'il s'agit d'un rejeu (replay).

Analyse de la trace d'attaque (étape par étape) :

    solve( St_B_1( $B, A, na, ~nb ) ▶₀ #i ) et case Resp_1 :

        L'agent B (identifié par $B) démarre l'étape 2 du protocole (après avoir reçu le message 1) en pensant répondre à une demande venant de A (avec le nonce na).

        B génère son nonce ~nb et envoie {B, ~nb, na}pk(A).

    solve( !KU( aenc(<k, ~nb, na, $X>, pk(~ltkB)) ) @ #vk ) :

        B attend ensuite le message 3 : {Kab, Nb, Na, A}pk(B).

        Tamarin cherche comment l'attaquant (!KU) a pu construire ou obtenir ce message.

    case Init_2 :

        Tamarin trouve que ce message a été généré légitimement par A (ou un autre agent jouant le rôle de A) dans une session précédente (étape 3 du protocole).

        Mais il y a une subtilité ici : le case Init_2 implique que A a généré ce message en réponse à un message qu'il a reçu précédemment.

    solve( (#i2 < #i) ∥ (#i < #i2) ) et case case_1 :

        Tamarin explore l'ordre des événements. Ici, il considère que l'événement #i2 (l'action de A) s'est produit avant l'événement #i (l'action de B qui termine la session).

    solve( St_B_1( $B.1, A2, na.1, ~nb.1 ) ▶₀ #i2 ) et case Resp_1 :

        Cela remonte à l'origine de l'état de A (qui a permis Init_2). A a répondu à un message qu'il pensait venir de B (ou d'un autre agent).

    solve( !KU( aenc(<$B, ~nb, ~na>, pk(~ltkA)) ) @ #vk.4 ) :

        Ici, on voit que l'attaquant a manipulé le message 2 {B, Nb, Na}pk(A).

        L'attaquant a pu intercepter, rejouer ou modifier ce message pour tromper A.

    solve( !KU( aenc(<k2, ~nb.1, na.1, $X.1>, pk(~ltkB.1)) ) @ #vk.5 ) et la suite (case Init_2, case Resp_1, case Init_1...) :

        La trace montre que l'attaquant a réussi à réutiliser ou rediriger des messages d'une session précédente (ou parallèle) entre A et B (ou d'autres agents).

        Plus précisément, l'attaquant a utilisé le message 3 {Kab, Nb, Na, A}pk(B) généré par A dans une session légitime (ou manipulée) pour le renvoyer à B dans la session actuelle.

    SOLVED // trace found :

Résumé de l'Attaque (Scénario probable) :

C'est une attaque par rejeu (Replay Attack) ou une variante de Man-in-the-Middle.

    Session 1 (Passée/Parallèle) :

        A et B (ou l'attaquant se faisant passer pour B) exécutent une partie du protocole. A génère un message 3 : {Kab, Nb, Na, A}pk(B).

    Session 2 (Actuelle, attaquée) :

        L'attaquant initie une session avec B (en se faisant passer pour A ou en relayant le message 1).

        B répond avec le message 2.

        L'attaquant intercepte ce message 2 et ne le transmet pas à A.

        À la place, l'attaquant rejoue le message 3 de la Session 1 (qui contient une clé Kab valide et chiffrée pour B) vers B.

        B déchiffre, voit que le format est correct (si les nonces ne sont pas vérifiés strictement ou s'ils sont prévisibles/réutilisés par l'attaquant dans la construction du message 1), et accepte la clé Kab.

Les nonces sont bien verifiés et pas previsibles donc B n'acceptera pas la clé, attaque non valide.