from code.tortor.core import Relay, RelayConfig, RelayAddress
from code.tortor.net import NetManager
from code.tortor.packet import *
import rsa
from rsa import PublicKey, PrivateKey
import itertools

# Pre-generated RSA key-pairs for faster local debugging
KEY_PAIRS = eval(
    """[(PublicKey(16851496889758249578005730675104882661664157087999109798696037039894169388301041965160345263807994084598728239701127746359317802025548686408098858381891224836526094151523082871775447537215108488903280601247111755495053310426012026013110000162688352548479927749125062124225706998977531044194096735804891518350752616720623857314391466230241328771812951201362836742748559840673002518678784117660998768988790475617625916683404064121879406269619881692348466266076746148698733952387014797463683276454828956464071927443917731301102015642493187456534559769054432248528867019825560139390670920694916886136389953589223838854403, 65537), PrivateKey(16851496889758249578005730675104882661664157087999109798696037039894169388301041965160345263807994084598728239701127746359317802025548686408098858381891224836526094151523082871775447537215108488903280601247111755495053310426012026013110000162688352548479927749125062124225706998977531044194096735804891518350752616720623857314391466230241328771812951201362836742748559840673002518678784117660998768988790475617625916683404064121879406269619881692348466266076746148698733952387014797463683276454828956464071927443917731301102015642493187456534559769054432248528867019825560139390670920694916886136389953589223838854403, 65537, 16765358502922278849888302050417146944563015860532492440828524452983499892518799124347846741395071948731346852693790245481487393803039892750367910710225851683647014524125426086111703775294864026328206993950198829390855027639300488580600244603927643359720283947975224691758312827064604408859313224129147301940443033344335253543614180177822854718880455776182285918330561841818888556561673214633709997779906072479545067713956155894542996752316491909476152758629836168395580012092633731341164115461671682223569365420203209655393253338370531455215786017629560813855304006471284195793794669890831681582654054922016260217361, 2004303521343057762567973975191209366653809066698032795663241612988961792569842397921602859821718660519270330462319780036536329633241871657408413670149940959079202375498747512863266123342731042142919122296257998876744772665068788175181829645510965879437887623100954787743737975648828137187796820927551479371575902601924016772509, 8407657178822038060871359429080737890290225376403503349835963146920731331879973331895619031243377261552916801847690951493572602851800467556256650667624498688975671673193560607386884518061578456347049528211485710398151115350297695476778707191539027451517986754951126284423897350537458260767)), (PublicKey(19663852844346151109191522498287800549003952248202609812777992265802838980519900438994976299541004717669124267382703391019147231956050946933568861852870299769709030527113188641683254373936895848756204476025318623464845475637519687750125420936906042679252361110979560432617791625709922972844192828826065873861195424937622143449231470906429934203057056097056317382766088087956105938719271918676091343038644392771187997577232595418600120719376473926381912772042384633922294932807822757879821713887920472857657063352245422187739437754045283510137531267200583525539679634632891373342946270554637999193074746615499194057617, 65537), PrivateKey(19663852844346151109191522498287800549003952248202609812777992265802838980519900438994976299541004717669124267382703391019147231956050946933568861852870299769709030527113188641683254373936895848756204476025318623464845475637519687750125420936906042679252361110979560432617791625709922972844192828826065873861195424937622143449231470906429934203057056097056317382766088087956105938719271918676091343038644392771187997577232595418600120719376473926381912772042384633922294932807822757879821713887920472857657063352245422187739437754045283510137531267200583525539679634632891373342946270554637999193074746615499194057617, 65537, 17949112789027197638800299966317848001014914191860727897523613429434631330281543007180027651420449276292817064000001255131413182020459889031538771285875262413957514445167846726624283124916504927968836903806805479239421792935100824886522162004479809651925397048705605447305514909642171782066745758542159685381156522733162261982661616298807239378883465978213420573658121172147184470634298115662593599980243872934085236367170741308621638531423618625662050765863938972616022564360248199943682589433929238970668800791329358855342420463467401383948774439890862815117043398549413223135655924779572353841736785534857722296153, 2958554185005406126501582699595077093073335927526822402673773782308310128320887497498658547134276817290072997339808237996891762219928429489929335522420585837369284370518658022865066186312742017311432725052417954731926683090152349614371551674945774091389623161190550592020380151822287208463659779585913570868809773143020473694707, 6646439988831984030005764078137572123775575262201016472829082092457502498922365524837104338694475962719524382641594119068229667906913925952480145637911366764284715094547342196795854544775828226763355807389050315076168102881961717004878814649511349449486712588215027874164613845619528993131)), (PublicKey(18149646873629971717960172107523882021917106808831685032354433277887525374092558452605586334515451662187169872271892943276885009839010318567426828979990106603666177020275387276954899720246433516425471171296286747319889203170443982804314670267245419033246578044326579202138136084978557569420499357139137327111372724960643356437924433420470111031712335686357921989557485643074509226459603397214124847001158303322270950578859422109553190873696701309762866648426945268936591123246062419233928116015352951684138690178340059294076976841328566733816485586341034074851478989717539522522983711339931658354388210823663301823481, 65537), PrivateKey(18149646873629971717960172107523882021917106808831685032354433277887525374092558452605586334515451662187169872271892943276885009839010318567426828979990106603666177020275387276954899720246433516425471171296286747319889203170443982804314670267245419033246578044326579202138136084978557569420499357139137327111372724960643356437924433420470111031712335686357921989557485643074509226459603397214124847001158303322270950578859422109553190873696701309762866648426945268936591123246062419233928116015352951684138690178340059294076976841328566733816485586341034074851478989717539522522983711339931658354388210823663301823481, 65537, 5222208692739069177496299272648699868582493600472085763082038364910280696084095621416658399224222530690502499068176529767493486588251179901825956544786508998357158552746280389421831088159161951557671389858157669624962245818164734176739273040106304327478076844864218746886778951652359126699570440071394372093145915440985928718756064016250587819206834101864837878425647222438499968345412407156961033999829404791286267171357195771449587301608269141643255112713966687140400334825626460874909107623382178283818170647805436899141150743693573902671364788342281088086944689358902351124309999640690886375077724834594711627925, 2789863001205897728729469922413796569374884555230152735512811543872980776931839174435178980081104224151467151120167094425346988568456614308944887782958427183489274495609652078285035991833511133496639478948295364503218816998966242701198898977668315100327404231960239000030009287483280415195618480693689958787460026464673454870287, 6505569221780754312782532795389320045615603870174366575068461504840689716340431901297505436757130371882015612056557271213189632695575272895792457420554607243418022106374667406481126308438624459505134326011328005161498274697490430925086708835819091119383873778661563789048943096602743174263)), (PublicKey(17892867299616191030830889974452071392478764071976116790605871075316110519129937952621545375431142136974272548484079040109805107390363040038580660061485323914814636523385933068377457067033041016559013004503392520753933214492128090890545895059916486949865370292720331524890760673988584539147341229837330954969492697014999645592367871206810628729705281027635186706431682723585374800806725287495493153219147879439876177516089310123017384151199044101726898239106269618420713364587501633608471011338507558724364131187555631071496965553149654515090824080451866309592467702902533138966889340332422719327229760441870570593551, 65537), PrivateKey(17892867299616191030830889974452071392478764071976116790605871075316110519129937952621545375431142136974272548484079040109805107390363040038580660061485323914814636523385933068377457067033041016559013004503392520753933214492128090890545895059916486949865370292720331524890760673988584539147341229837330954969492697014999645592367871206810628729705281027635186706431682723585374800806725287495493153219147879439876177516089310123017384151199044101726898239106269618420713364587501633608471011338507558724364131187555631071496965553149654515090824080451866309592467702902533138966889340332422719327229760441870570593551, 65537, 17092647667115846860188881055595257359926842905383779663284421998889793783063748652849908750388972406845160858299803963945778088000382508882850615740869282832764470973390599595325374630188604389622557763705073350234535343798070879934899618629493745242889838908495187076724765594331893795225537720358012754405822801806918261265857389810085898723359520470079607797902467135732205199960020818365097858703058914075145652039170351711431028054701896404346643083944865606255342160083412880457682571681138877672249242910148630544474952923235482347355522071656653961468105679901458187634372353916370518644189114805918876983889, 2593672429046095922525809463966164958228529074020994254185962170465909921321015384453790151099928043380652720360320646825064587374089806926623843897206004301149922260805095217048522383691123673975565543883873494933574769609736163794774971967777799344165618976749164903510515436952721929919659974470874180313044443888857263027003, 6898661179891884828124833471751687657803577279980455383890743568672040598942045065010922511243547854859896743450948233448171266412622868976632102428074123793606635070089473399992974129293594357301251328558070444243435784305804452551376251770629257748729845709851023115002777866058296211517)), (PublicKey(18021727016427737269827759097575470402598023292549401950577243591768689579369303552422884287197719606651235462903369731854943070368801545316767284586785369088263936256354385511595058669178242329193176505114207628113513204731249147120275242988199264571413676319821739847893934860030590712990512936683233600204852393895088051246829121831876258512841055318861698454211310324716524941046865476660119273713894311292910981711824770595683715673632517019052596672338236988806798691694582144377588604560533353808642167998984169761293395020072224413322501718043079295036324963510705549968243859867046927678939442571659802357247, 65537), PrivateKey(18021727016427737269827759097575470402598023292549401950577243591768689579369303552422884287197719606651235462903369731854943070368801545316767284586785369088263936256354385511595058669178242329193176505114207628113513204731249147120275242988199264571413676319821739847893934860030590712990512936683233600204852393895088051246829121831876258512841055318861698454211310324716524941046865476660119273713894311292910981711824770595683715673632517019052596672338236988806798691694582144377588604560533353808642167998984169761293395020072224413322501718043079295036324963510705549968243859867046927678939442571659802357247, 65537, 10750284510737842147590619255697017561364833950271240976179360681395320970075889239336866782484820029943747794173433881580437682423637450792891042062282179824169405435188036486111619750871327732692647547048763797755003818083883213414102573346058898777100664693945574219350374436090085193609105272385506464003624895120966530121633545859828168373193278297659135579149864080107835371702761650675629126989162444300824073283241810570065620377161442581002936815636008856529230258040176992600142463107899598802475488537749849511212823067152350329436002726950800786272322537247268677657733245913691546781084322381699482979825, 2332340266163534941498304992883531766044352560600516550036132392902159871715633289155975357185460358820079637273101616498177296673958423022543008123031826786003677079273342330055082122232333856920213669409364962072846832857609957139375037544441537805106259227784978715022592064325065468580497884936082291191238829368174336239349, 7726885857041633496899193578949017581760776850077215843706997915531883448294124371059789024058127914615343999722564115711490062028492335368175273581062438886352870263911625819853346797932459733588823906490573456831188243668479893209384351491000307313594858712475791616571456915322601840803)), (PublicKey(20522643079603602868310887223027603175681480933262824335705723592617023935117540981325683986067924326970196344796535016977018182101884081305614646354645717202326076675540216354435720547610710046905789833997614499132255484285937216204886087828574196290458173325227907060723418083056048218917350613736967703595173859331011465147576800978196269186912512551679953331009056973793282240567203584411540195516454391589184882242627963824918317307494105702613132545249368812528373864030122322965842080120440988003410636342236903303994488079119467869723055124018462390636471911267746041088627470850195699610328820526328488460161, 65537), PrivateKey(20522643079603602868310887223027603175681480933262824335705723592617023935117540981325683986067924326970196344796535016977018182101884081305614646354645717202326076675540216354435720547610710046905789833997614499132255484285937216204886087828574196290458173325227907060723418083056048218917350613736967703595173859331011465147576800978196269186912512551679953331009056973793282240567203584411540195516454391589184882242627963824918317307494105702613132545249368812528373864030122322965842080120440988003410636342236903303994488079119467869723055124018462390636471911267746041088627470850195699610328820526328488460161, 65537, 17097453186799473778276487045334453908311841821798632007952710719643817840814846880989380349349567424939282393602789498938435017235771685539546425321838068778396958365622782134303308149274412283916096543119699620643636681363624915201650602092746426343328590038972160727656711535724509463426025429115381987900108892683235974113247420878751463857993002804127659153700372195294700532292744092336975049783518017682522468031830775615605099972431319490238294790036495353394808283255794816535894868637019093582211954843509910615857802098236238954763509276695750623664447880268855243436867199962299872729099761100786808149837, 2142852643636519122757945124135221343470148281313777888929816310774511055358827854731858551237619521106507698324065493528938753143314532777220145068492353696126116212093281140856129142093744564285461227745749781706533675010105063747747359385800821270646190731705952645315230430337972471304190776276856186615606136082008194838723, 9577253545897461808271347150714204512272516137765952285506890106103325638653109403686943264369685896323395468488896726504834870956747098118964433657562672482594409292138039826842255850729084706680785424905151986019187375026306543374375774063714372928780626075212317275991369891631324121707)), (PublicKey(28335518319097580352030403868662513878713935318814633033204137007513910237966858993640389128325830313043506110526329668701382850301374462282938915669945162279159382839517458144322083164997361517676228265167503443238400698464905134463833254945882207137151135861625674755151550732318756073123966080772108605024894602097441460899134629422497592001603973869698591258436575297103887596424992644918245060682114375196189000703432474716015242984509016820078754757978178140760658016297690448394874919293089828153676661952680193519868546138163127161417381469497186003579906834628615683570255550574040399100442863429007197290963, 65537), PrivateKey(28335518319097580352030403868662513878713935318814633033204137007513910237966858993640389128325830313043506110526329668701382850301374462282938915669945162279159382839517458144322083164997361517676228265167503443238400698464905134463833254945882207137151135861625674755151550732318756073123966080772108605024894602097441460899134629422497592001603973869698591258436575297103887596424992644918245060682114375196189000703432474716015242984509016820078754757978178140760658016297690448394874919293089828153676661952680193519868546138163127161417381469497186003579906834628615683570255550574040399100442863429007197290963, 65537, 25796705685474726211207318718033307758570989682119643558999112479260836692987055279545200685743330723526264432069723357539527408383531551522217226962590263627966562050747045793688711598632338601891330995334224833923114846177099422429842854514946700166899957599278207489908254488972619758346529820616491902148210055941025710804913439068784519677773541282256758366408492630155511054375078427426455548950428223682939706826015459401739310609833708477794302326117789784916928491221831742360325261131512112366989854640631667906322004787837619983039380674578557030286257871583013147786709870056922290451099818339579197811673, 3099159566325821297630000803433214707528871080638596277715969141717180873491434504356227349470771244811953045118197562237221574207431715143871578404953850217481119458476791532096372737117947989015935101846237878903423237267811192231667404268661306602741890524002809370604202168926132150541507666508531945443541814506645431253573, 9142968508940144867731954743143845779576701529999508320524678439525614632646981474699940260241517758487598218427675569174268308019251535604690164301586305870708247200042105821184219898426738327057670357216324860553444665935927088119080478491624022989401453931920652612842911077377237637431)), (PublicKey(26553643712191299841755100085922923925707355367490175380480462234395583369750864320865506359455050531785278062767134790246045285455780121213078143162520672663386548092579578842550010645214599624455828621026187601445783331529146428422518347441375329669826352224628829661112842817660821904640874855881959253225304829437617810161192576765796384724227471696030980979331744699445843320636983145067874621282858335054154653909745498636242056260779413132418856998284133007156477357903711359579334981574649303501607334145769393300061024984755808962501606711985420107749588082004388053418601940111844671645083080855707511851837, 65537), PrivateKey(26553643712191299841755100085922923925707355367490175380480462234395583369750864320865506359455050531785278062767134790246045285455780121213078143162520672663386548092579578842550010645214599624455828621026187601445783331529146428422518347441375329669826352224628829661112842817660821904640874855881959253225304829437617810161192576765796384724227471696030980979331744699445843320636983145067874621282858335054154653909745498636242056260779413132418856998284133007156477357903711359579334981574649303501607334145769393300061024984755808962501606711985420107749588082004388053418601940111844671645083080855707511851837, 65537, 17689733806464625342799146585156398043797902487825519280891358792036729937643205155087782590808360257835195999518029585457716056014150176116743087576112006477004694900926566859418854460382217977688046105162020700964690178899896746340649572749598652568543243330138619451671372162581007436356298624066238528731114979437328744049005367172414546427788620017462010382448011969147207917016894046149628891080737439466268684996765750892944858532679743558685207175223369373068980657904766498489172397213825860273817382433628669820629747506283651487222052212287665782175332349303520183473676370346991351504935543557169135931473, 3157427447944721446764233757722851417719559712701846915508988733114954712639255192149311863117368944783245708913457461795617356536199865416237254980353395065728577216775434503536348103062416626818377975159118197328929189071142600431128527469489488721773865555379261061481169045536923161067788627587449898078015181118972298265387, 8409898295359401985024646736278799113576075734447965592537125101206360038702532207212267400274057034230014435345112120617159702658172653807445210473345076061806951532285448711267934526007412794846108089720931612279009231807790920605918895003772673745354579509489317690316623554733526423351)), (PublicKey(23659936057983624181773984755707559256699042492358633276123138409126372849320340689447450957026873515913525959830196633607978026080582334696737639345095871699301018063483328027470176001534215727434987876879222819310097979462235543819748262806292428444186611147679719534193822014565591695748848762292921042252924409257775188823152290409773279706451464051043138567518083847974538125841965298873869961171503143374480122738326152549500765627389977362845859386224192895782634870209192095260528282355426612138544401299089440309161218245567783712884070398300068534615556044250622019206768606456443370686077136602305135628271, 65537), PrivateKey(23659936057983624181773984755707559256699042492358633276123138409126372849320340689447450957026873515913525959830196633607978026080582334696737639345095871699301018063483328027470176001534215727434987876879222819310097979462235543819748262806292428444186611147679719534193822014565591695748848762292921042252924409257775188823152290409773279706451464051043138567518083847974538125841965298873869961171503143374480122738326152549500765627389977362845859386224192895782634870209192095260528282355426612138544401299089440309161218245567783712884070398300068534615556044250622019206768606456443370686077136602305135628271, 65537, 9672353126714638434442965036161510713115961158662625734072220642649400817538040614487634558198635812416729290565186508500922338141064771216183145907408160192985227824844672849107846795445392797495127869712500385659339686982196540733001136107941876235968196375614310172270944343107577898171046349450242712542907565959958429436659176738241014027603775644914775632652577785510438185659853007278660689515515430954397124727665258569673215123260272351221213802539306198896103054157919856216173283805149730237473935831183665525830513949639944939585302579839365170954591632125071581409195101294726106103990346402262749348673, 2511624194960581969088445152154272505199735498362788549577173656265787533810691449364837241181808116594011358411349621221133407018586086197193204219129181518234875634363699016750306194966475742702237620400065605238486560766309409976638525183359312156732907009737065228004664322749282718578392116735902173112799013352304672760131, 9420173649169257536105696330812864210826620429737187527065716990907213958334516537553778899905860213136409589318258181055269770932660557255159898729294673816899631023064132065281439645638947637451239168600190296610928423837246543067629859953831976396724528181556992745821593981371998995941)), (PublicKey(20971216011546544444145579822999887565955290056602588741588061965704157190788360664296248971672972484050249249983088838681280508512861064233556426894121115829785792563950787902927321321066989035858555293092073269077405689171667262285967000617790935136749531421702505512088421979645773954989454091666133367215025025141405833180481221894569436312336510802298447731355507951693769571348929238686949697495434683512453465848619724375315934162384537241790786744735043193939067404796525395650240425031506962498852770113061307992622141832441224872804014886094022893348678760840258273778429204716642635076644449109643907789973, 65537), PrivateKey(20971216011546544444145579822999887565955290056602588741588061965704157190788360664296248971672972484050249249983088838681280508512861064233556426894121115829785792563950787902927321321066989035858555293092073269077405689171667262285967000617790935136749531421702505512088421979645773954989454091666133367215025025141405833180481221894569436312336510802298447731355507951693769571348929238686949697495434683512453465848619724375315934162384537241790786744735043193939067404796525395650240425031506962498852770113061307992622141832441224872804014886094022893348678760840258273778429204716642635076644449109643907789973, 65537, 1243802991239779334641406667561843889236129399423444198522251504656790194860832169646451924148081908624186624878835868531579677687252864132868972204059520228731516177061457078881830080336106113834661403852005566274072293724312535644072107838340988523681972452754285959465457622944033498070301992981487380831521244934853531282770392775720219534397413490738878205443036536883900402835661657984496489121781023552511405558907639149958181941130042380096634786271390750563719474555352140444712605490586982196322185293465000667499496659164840611519536318617830454916964522827150523451842162596463919652456463198791814559073, 2733815353362984514894377007756262900328649554005802159820709355119259312957878340381153330225145628299107525075783836619347806767462199407867372583476505850260184251495266312345290563079179412524994164897103820813673241684286046509352370892582218472625806263890019848980707442940542213429623477561242653464649926237326599524573, 7671043322567101884649416679095557548572364654478679857830927256906641785701029408943069393961757802331666833387170196677720067752734015708908510373349783401775710600932842688429577932810314545807843347451967769574696475752561180747414607706002693880223321679594501225310903459088815659801))]""")


def __test4__():
    """
    Test build-circuit
    """

    key_pairs = KEY_PAIRS[:4]
    ips = [b"192.168.1.1", b"192.168.2.2", b"192.168.3.1", b"192.168.4.2"]

    addresses = [RelayAddress(ips[i], key_pairs[i][0]) for i in range(4)]
    net_graph = {(ips[0], ips[1], 1), (ips[1], ips[2], 1), (ips[2], ips[3], 1), (ips[0], ips[3], 1)}

    config = RelayConfig(relay_list=addresses, net_graph=net_graph)

    relays = [Relay(ips[i], key_pairs[i][0], key_pairs[i][1], config) for i in range(4)]

    print(relays[0].build_circuit(ips[0], ips[1]))


def __test5__():
    """
    Test register and hidden circuit
    """

    key_pairs = KEY_PAIRS[:7]
    ips = [b"192.168.1.%d" % (i,) for i in range(len(key_pairs))]

    addresses = [RelayAddress(ips[i], key_pairs[i][0]) for i in range(len(key_pairs))]
    net_graph = set([(ips[i], ips[i + 1], 1) for i in range(len(key_pairs) - 1)])
    net_graph = net_graph.union(set([(r2, r1, d) for r1, r2, d in net_graph]))

    config = RelayConfig(relay_list=addresses, net_graph=net_graph)

    relays = [Relay(ips[i], key_pairs[i][0], key_pairs[i][1], config) for i in range(len(key_pairs))]

    # register on net
    netman = NetManager()
    for r in relays:
        netman.register_node(r)

    # build circuit
    fpath = relays[0].build_circuit(relays[0].ip, relays[3].ip)
    rpath = relays[0].build_circuit(relays[3].ip, relays[0].ip)

    # send register
    hidden_pub, hidden_priv = rsa.newkeys(2048, poolsize=8)
    relays[0].hidden_keypair = (hidden_pub, hidden_priv)
    relays[0].register_on(relays[3].address, fpath, rpath)

    # send data
    mpath = relays[6].build_circuit(relays[6].ip, relays[3].ip)
    relays[6].send_data_hidden(b"OMG IT'S FINALLY WORKING", relays[3].address, hidden_pub, mpath)


def __test6__():
    """
    send a plain message through two hops
    """

    key_pairs = KEY_PAIRS[:4]
    ips = [b"192.168.1.1", b"192.168.2.2", b"192.168.3.1", b"192.168.4.2"]

    addresses = [RelayAddress(ips[i], key_pairs[i][0]) for i in range(4)]
    net_graph = {(ips[0], ips[1], 1), (ips[1], ips[2], 1), (ips[2], ips[3], 1), (ips[0], ips[3], 8)}
    net_graph = net_graph.union(set([(r2, r1, d) for r1, r2, d in net_graph]))

    config = RelayConfig(relay_list=addresses, net_graph=net_graph)

    relays = [Relay(ips[i], key_pairs[i][0], key_pairs[i][1], config) for i in range(4)]

    # register on net
    netman = NetManager()
    for r in relays:
        netman.register_node(r)

    # build circuit
    fpath = relays[0].build_circuit(relays[0].ip, relays[3].ip)

    # simple data send
    relays[0].send_data_simple(b"THIS ACTUALLY WORKS!", relays[3].address, fpath)


if __name__ == "__main__":
    __test6__()
    # __test5__()