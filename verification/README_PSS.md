1. Le Lemme secrecy_Kab

Ce lemme dit : "Si A ou B déclarent que la clé k est secrète (Secret(...)), alors l'attaquant (K) ne doit pas la connaître, SAUF si l'une des clés privées à long terme a été compromise (Reveal)".

Si Tamarin trouve une trace où l'attaquant connaît k SANS utiliser de Reveal, c'est une violation grave de la confidentialité.


La trace:

    solve( Secret( A, B, k ) @ #i ) / case B_2_send :

        B déclare que la clé k qu'il utilise est secrète.

        Cette clé lui a été envoyée dans le message 2 (S -> A) puis relayée par A dans le message 3.

    solve( St_B_1( $B, $A, ~nb_gen ) ▶₁ #i ) / case B_1_send :

        B a initialisé le protocole en envoyant le message 1 : {Nb}pk(S), {B}Nb, {A}Nb.

        Il attendait une réponse.

    solve( !KU( aenc(<k, $A, z, ~nb_gen>, pk(~ltkB)) ) @ #vk.1 ) :

        B a besoin de recevoir le message 3 pour continuer.

        Ce message est censé être {Kab, A, NA, NB}pk(B).

        Tamarin cherche comment l'attaquant (!KU) a pu construire ce message ou connaître son contenu k.

    case c_aenc :

        L'attaquant a construit lui-même ce message chiffré pour B.

        Pour ce faire, il a utilisé la clé publique de B (pk(~ltkB)), son identité $A, un nonce z, le nonce ~nb_gen (qu'il a appris), et... la clé k !

        Cela signifie que l'attaquant connaissait déjà k avant d'envoyer ce message à B.

    solve( !KU( ~nb_gen ) @ #vk.8 ) :

        Comment l'attaquant a-t-il appris ~nb_gen (le nonce de B) ?

        case B_1_send : B a envoyé ~nb dans le message 1 (Out(~nb)).


        Si Nb est envoyé en clair, l'attaquant l'apprend immédiatement.

        C'est une attaque par usurpation d'identité sur l'établissement de la clé. La confidentialité de la clé Kab (du point de vue de B) est violée car c'est l'attaquant qui l'a choisie.


2. Le Lemme secrecy_Kab_PFS

Le lemme dit : "Pour toute session entre A et B où une clé k est déclarée secrète (Secret(...)) au temps #i, l'attaquant ne doit pas connaître k, SAUF si :

    A a été compromis (Reveal(A)) AVANT le temps #i (#r < #i).

    OU B a été compromis (Reveal(B)) AVANT le temps #i (#r < #i)."


La trace :

    solve( Secret( A, B, k ) @ #i ) / case A_1_send :

        A déclare que la clé k (qu'il vient de générer) est secrète dans l'étape 2.

        Il envoie le message 2 : {KAB, A, NA, NB}pk(B).

    solve( !Pk( $B, pkB ) ▶₁ #i ) / case Register_pk :

        A utilise la clé publique de B pour chiffrer ce message.

    solve( !KU( ~kab ) @ #vk ) :

        Tamarin suppose que l'attaquant connaît ~kab (la clé k).

        Il cherche comment l'attaquant a pu l'apprendre.

    case A_1_send :

        L'attaquant a appris ~kab en déchiffrant le message envoyé par A : {KAB, A, NA, NB}pk(B).

        Pour déchiffrer ce message, l'attaquant a besoin de la clé privée de B (~ltkB ou ~ltkX).

    solve( !KU( ~ltkX ) @ #vk.2 ) :

        Comment l'attaquant a-t-il obtenu la clé privée de B ?

    case Reveal_ltk :

        L'attaquant a utilisé la règle Reveal_ltk pour voler la clé privée de B.

        Notez que le lemme autorise l'attaquant à connaître k si le Reveal a lieu avant. Mais ici, Tamarin a trouvé une trace où le Reveal a lieu après ou à un moment qui contredit la garantie de PFS.

        L'attaquant enregistre le trafic (message 2), attend plus tard pour voler la clé de B, puis déchiffre le message enregistré pour retrouver KAB.

L'attaque montre que si un attaquant enregistre le message 2 et compromet plus tard la clé privée de B, il peut retrouver la clé de session KAB. L'attaque est pas valide car on autorise les clés de session anciennes peuvent être compromises.

3. Le lemme aliveness_B_authenticates_A 

La trace : 

    solve( St_B_2(...) ▶₁ #i ) / case B_2_send :

        B termine l'étape 3 et envoie le message 3 : {∣{NB​,NA​−1}pk(A)​∣}KAB​​.

        B est prêt à recevoir le message 4.

    solve( !KU( senc(decr(~nb_gen), ~kab) ) @ #vk ) :

        B attend le message 4 : {NB​−1}KAB​​.

        Tamarin cherche comment l'attaquant a pu construire ce message.

    case A_2_receive :

        Tamarin trouve que ce message a été généré par A à l'étape 4 !

        Cela semble contredire l'attaque (si A a généré le message, A est vivant, non ?).

        MAIS, regardons pourquoi A a généré ce message.

    solve( !KU( aenc(<~kab, $A, ~na_rec, ~nb_gen>, pk(~ltkB)) ) @ #vk.1 ) :

        Pour que A arrive à l'étape 4, il a dû passer par l'étape 2 (A_1_send) et envoyer le message 2 : {KAB​,A,NA​,NB​}pk(B)​.

        Tamarin regarde d'où vient ce message 2 reçu par B.

    case c_aenc :

        L'attaquant a forgé le message 2 !

        L'attaquant a créé {KAB​,A,NA​,NB​}pk(B)​ lui-même.

        Il a utilisé une clé KAB​ qu'il connaissait (ou a générée), l'identité de A, un nonce NA​ (intercepté ou généré), et le nonce NB​ envoyé par B à l'étape 1.

    La suite de la trace (case A_1_send, case Reveal_ltk...) :

        La trace montre que A a pu participer à une session différente ou que ses clés ont été compromises dans le passé ou que l'attaquant utilise une session parallèle.

        Le point clé est que B interagit avec l'attaquant, qui se fait passer pour A.

        L'attaquant a réussi à compléter les étapes 2 et 3 sans que le vrai A ne soit impliqué dans cette session spécifique avec B.


L'attaque est une usurpation d'identité rendue possible par le manque d'authentification de l'origine du message 2.

    B→A:NB​ (Message 1)

        B envoie son nonce. L'attaquant l'intercepte.

    Attaquant →B:{KAtt​,A,NAtt​,NB​}pk(B)​ (Faux Message 2)

        L'attaquant génère sa propre clé KAtt​ et son nonce NAtt​.

        Il crée le message 2 en prétendant être A. Comme ce message est chiffré avec la clé publique de B (pour la confidentialité) mais pas signé par A, n'importe qui peut le créer !

        B déchiffre, voit son nonce NB​, et croit que le message vient de A.

    B→A:{∣{NB​,NAtt​−1}pk(A)​∣}KAtt​​ (Message 3)

        B répond en utilisant la clé KAtt​ fournie par l'attaquant.

        L'attaquant reçoit ce message. Comme il connaît KAtt​, il peut déchiffrer la couche externe.

        Il obtient {NB​,NAtt​−1}pk(A)​. Il ne peut pas déchiffrer ceci (c'est pour A), mais il n'en a pas besoin pour l'étape suivante si le protocole est mal conçu ou s'il peut utiliser A comme oracle dans une autre session.

    Attaquant →B:{NB​−1}KAtt​​ (Message 4)

        L'attaquant calcule NB​−1.

        Il chiffre le résultat avec KAtt​.

        Il l'envoie à B.

    B accepte et finit.

        B déchiffre, vérifie NB​−1, et croit que A est vivant et authentifié.

        En réalité, A n'a jamais vu le message 1 ni envoyé le message 2. C'est l'attaquant qui a tout fait.

Conclusion

Le protocole PSS est vulnérable à une usurpation d'identité de A vers B. La cause racine est que le message 2, qui établit la clé de session KAB​, n'est pas authentifié. Il assure la confidentialité (seul B peut le lire), mais pas l'origine (n'importe qui peut l'écrire). B ne peut pas savoir si c'est A ou un attaquant qui a généré ce message. Attaque non valide car autorisée par l'énoncé, tant que à la fin du processus A a bien authentifié et B et B a bien authentifié A alors c'est bon.

4. Le Lemme : agreement_B_authenticates_A

Ce lemme vérifie la propriété d'Accord Faible (Weak Agreement) : "Si B termine le protocole (Commit_B) en pensant parler à A avec la clé k et les nonces nA,nB, alors A doit avoir commencé une session (Running_A) correspondant à ces mêmes paramètres (clé et nonces), sauf si une clé privée a été compromise (Reveal)."

Une attaque ici signifie que B est d'accord sur une clé et des nonces avec quelqu'un qu'il croit être A, mais A n'a jamais vu cette clé ou ces nonces (ou n'a jamais lancé le protocole avec ces paramètres).


La trace :

    L'Usurpation (Man-in-the-Middle) :

        L'attaquant intercepte le début de l'échange ou initie lui-même la connexion avec B.

        Il forge le Message 2 : {KAtt​,A,NAtt​,NB​}pk(B)​.

        Il choisit lui-même la clé KAtt​ et le nonce NAtt​.

        Il n'a pas besoin de la clé privée de A pour faire cela, car le message est simplement chiffré avec la clé publique de B.

    La Tromperie de B :

        B reçoit ce message, le déchiffre, et enregistre : "Je parle à A, la clé est KAtt​, les nonces sont NAtt​ et NB​".

        B termine le protocole (Commit_B) sur ces valeurs.

    L'Absence de A :

        A n'a jamais généré KAtt​.

        A n'a jamais envoyé NAtt​ dans une session avec B.

        Par conséquent, l'événement Running_A(A, B, K_att, ...) n'existe pas dans la trace.

Même sans compromission complexe, l'attaque reste valide : B accepte une clé qui ne vient pas de A. Il y a donc un désaccord total (non-agreement) sur la clé de session établie. Car en grande partie Nb est public.

Le protocole PSS ne garantit pas l'Agreement (Accord) de B vers A. Un attaquant peut forcer B à accepter une clé de session et des nonces de son choix en se faisant passer pour A. B croit partager ces valeurs avec A, alors que A ne les connaît pas. C'est une rupture critique de l'authentification mutuelle.

5. Le Lemme : injective_agreement_A_B

Ce lemme vise à prouver deux choses simultanément :

    Accord (Agreement) : Si A termine le protocole (Commit_A) en pensant parler à B avec la clé k et les nonces nA,nB, alors B doit avoir lui aussi terminé (Commit_B) avec les mêmes paramètres.

    Injectivité (Unicité) : Il doit y avoir une correspondance 1 pour 1. Pour chaque engagement de A, il doit y avoir une exécution unique de B. A ne doit pas accepter deux fois le même engagement de B.

La trace


    solve( St_A_1( $A, $B, ~kab, ~na, nB ) ▶₁ #i ) / case A_1_send :

        A est à l'étape 4 (A_2_receive qui consomme St_A_1) et s'apprête à faire son Commit_A.

        A a reçu un message 3 (chiffré) qu'il pense venir de B.

    solve( !KU( senc(aenc(<nB, decr(~na)>, pk(~ltkA)), ~kab) ) @ #vk ) :

        A a reçu le message 3 : {∣{NB​,NA​−1}pk(A)​∣}KAB​​.

        Tamarin cherche comment l'attaquant a pu construire ce message.

    case B_2_send :

        Tamarin trouve que ce message a été légitimement généré par B à l'étape 3.

        Mais attention : B génère ce message en réponse au message 2 qu'il a reçu.

    solve( !KU( aenc(<~kab, $A, ~na, ~nb_gen>, pk(~ltkB)) ) @ #vk.2 ) :

        B a reçu le message 2 : {KAB​,A,NA​,NB​}pk(B)​.

        Tamarin cherche d'où vient ce message.

    case A_1_send :

        Ce message a été généré par A à l'étape 2.

        Cependant, regardez bien :

        A a généré ce message en réponse à un message 1 (NB​).

        B a reçu ce message après avoir envoyé un message 1 (NB​).

    solve( !KU( ~nb_gen ) @ #vk.2 ) / case B_1_send :

        B a envoyé NB​ en clair. L'attaquant l'a vu.

Le Nœud du Problème : Désynchronisation et Usurpation

L'attaque ici est subtile. Bien que A et B semblent interagir, l'attaquant s'est inséré au milieu pour briser l'accord sur qui a initié quoi et quand.

    Interception : L'attaquant intercepte les messages ou initie des sessions parallèles.

    Désaccord sur l'état :

        A fait Commit_A. Il croit que le protocole est fini et réussi.

        Mais pour que l'injectivité soit valide, il faut que B ait fait Commit_B AVANT ou PENDANT la session de A (pour le même échange).

        Or, dans la trace, B est encore à l'étape B_2_send. Il n'a pas encore fait son Commit_B (qui arrive à l'étape 5 B_3_receive).

        Le Lemme exige : (Commit_B(...) @ #j) ∧ (#j < #i).

        La Réalité : A commit à l'étape 4. B ne commit qu'à l'étape 5. Donc au moment où A commit, B n'a pas encore commit. La condition temporelle #j < #i est violée.

C'est une attaque sur la synchronisation de l'accord. A pense que l'échange est terminé et sécurisé, alors que B attend encore une confirmation (le message 4). Si l'attaquant bloque le message 4, A pense avoir réussi (Commit), mais B échoue (pas de Commit). Il n'y a pas d'accord mutuel complet au moment où A s'engage.

De plus, comme vu précédemment, l'attaquant peut manipuler les messages intermédiaires (notamment le message 2 non authentifié) pour faire croire à B qu'il parle à A dans une autre session, brisant l'unicité.

Le protocole PSS échoue à garantir l'Accord Injectif de A vers B pour deux raisons :

    Problème temporel : A s'engage (Commit) avant que B ne s'engage. Si le dernier message est perdu ou intercepté, A croit à un succès alors que B n'a pas fini. L'accord n'est pas atomique.

    Faiblesse du Msg 2 : Comme pour les autres attaques, l'absence d'authentification sur le message 2 permet à un attaquant de manipuler la session, rendant impossible la garantie d'une correspondance unique 1-pour-1 entre les vues de A et B.


6. Le Lemme : injective_agreement_B_A

Ce lemme vérifie l'accord injectif du point de vue de B : "Si B termine le protocole (Commit_B) en pensant parler à A avec certains paramètres, alors :

    A doit avoir participé activement (Running_A) avec les mêmes paramètres.

    Il ne doit pas y avoir d'autre session terminée par B qui correspond à cette même action de A (unicité)."

La trace :

L'attaque ici est assez complexe car elle implique deux sessions entrelacées (#i et #i2) pour briser l'unicité.

    solve( St_B_2(...) ▶₁ #i ) / case B_2_send :

        B est dans une session courante (appelons-la Session 2) et s'apprête à terminer (Commit_B).

        B a reçu le message 4 : {NB​−1}KAB​​.

    solve( !KU( senc(decr(~nb_gen), ~kab) ) @ #vk ) :

        Tamarin cherche d'où vient ce message 4.

    case A_2_receive :

        Ce message a été généré par A à la fin d'une session.

    solve( (#i2 < #i) ∥ (#i < #i2) ) / case case_1 :

        Tamarin explore une autre session (Session 1, au temps #i2) où B a déjà terminé (Commit_B) avec les mêmes paramètres.

        C'est le cœur de l'attaque contre l'injectivité : montrer que B accepte deux fois la même interaction.

    Les étapes suivantes (solve( St_B_2(...) ▶₁ #i2 ), case B_2_send...) :

        Tamarin remonte le fil de la Session 1.

        On voit que l'attaquant (!KU) a manipulé les messages pour que les paramètres de la Session 1 (clés, nonces) soient réutilisés ou confondus avec ceux de la Session 2.

Scénario probable de l'attaque (Rejeu)

    Session 1 (Légitime) :

        B envoie NB​.

        A répond avec la clé et les nonces.

        L'échange se termine correctement. B fait Commit_B.

    Session 2 (Attaque) :

        L'attaquant initie une nouvelle session avec B (ou laisse B en initier une).

        L'attaquant s'arrange pour que B utilise le même nonce NB​ que dans la Session 1 (si le générateur de nonces est prévisible ou manipulable) ou rejoue simplement l'intégralité des messages de A vers B.

        Point clé : Comme le message 4 {NB​−1}KAB​​ ne contient pas de preuve de fraîcheur liée spécifiquement à la Session 2 (autre que NB​ qui est répété), si l'attaquant peut forcer la réutilisation de NB​ ou si KAB​ est réutilisée, il peut rejouer le message 4.

    Résultat :

        B reçoit le message 4 (copié de la Session 1).

        B accepte et fait Commit_B à nouveau.

        Violation : B a commis deux fois (Session 1 et Session 2) pour une seule exécution de A (Session 1). L'injectivité est brisée.

Le protocole PSS est vulnérable aux attaques par rejeu (Replay Attacks). Si un attaquant peut rejouer d'anciens messages, il peut amener B à accepter une session comme nouvelle alors qu'elle est une copie d'une ancienne, sauf que dans les spécifications B verifie bien que le nonce est unique donc l'attaque est pas valide.