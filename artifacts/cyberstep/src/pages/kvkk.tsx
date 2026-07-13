import { Shield, FileText, Database, Eye, Lock, UserCheck, Trash2, Mail, ChevronRight, Globe } from "lucide-react";
import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useLanguage } from "@/contexts/language-context";

// ─── Web Veri Toplama Aydınlatma Metni (TR + EN) ─────────────────────────────
const WEB_SCRAPING_NOTICE = {
  tr: {
    badge: "Kamuya Açık Veri İşleme",
    title: "KİŞİSEL VERİLERİN İŞLENMESİNE İLİŞKİN AYDINLATMA METNİ",
    controller: { label: "Veri Sorumlusu", value: "CyberStep (cyberstep.io)" },
    rows: [
      {
        heading: "Kapsam",
        body: "CyberStep, Türkiye'deki kurumsal internet varlıklarının siber risk görünürlüğünü artırmak amacıyla, kamuya açık kurumsal web sitelerinde yayımlanan iletişim bilgilerini (kurumsal e-posta, telefon, adres) otomatik yöntemlerle derler ve analiz eder.",
      },
      {
        heading: "İşlenen Veriler",
        body: "Kamuya açık web sitelerinde yayımlanmış kurumsal iletişim bilgileri, alan adı (domain), şehir ve sektör bilgisi.",
      },
      {
        heading: "İşleme Amacı",
        body: "Siber risk analizi, \"Türkiye Siber Risk Endeksi\" gibi toplu raporların hazırlanması ve kurumsal güvenlik değerlendirmesi.",
      },
      {
        heading: "Hukuki Dayanak",
        body: "6698 sayılı KVKK'nın 5/2-(f) maddesi uyarınca, ilgili kişinin temel hak ve özgürlüklerine zarar vermemek kaydıyla veri sorumlusunun meşru menfaati. Verileriniz açık rızanız aranmaksızın bu dayanakla işlenmektedir.",
      },
      {
        heading: "Haklarınız",
        body: "KVKK'nın 11. maddesi kapsamında, tarafınıza ait kişisel verilerin işlenip işlenmediğini öğrenme, işlenmişse buna itiraz etme ve silinmesini/yok edilmesini talep etme haklarına sahipsiniz. İtirazınız üzerine, size ait kişisel iletişim verileri (e-posta, telefon, adres) sistemlerimizden silinir; kişisel nitelik taşımayan alan adı, şehir ve sektör bilgileri anonim olarak kalabilir.",
      },
      {
        heading: "Başvuru",
        body: "Taleplerinizi kvkk@cyberstep.io adresine iletebilirsiniz. Başvurunuz en kısa sürede ve her hâlükârda yasal süreler içinde sonuçlandırılacaktır.",
      },
    ],
  },
  en: {
    badge: "Public Data Processing",
    title: "PERSONAL DATA PROCESSING NOTICE",
    controller: { label: "Data Controller", value: "CyberStep (cyberstep.io)" },
    rows: [
      {
        heading: "Scope",
        body: "CyberStep collects and analyzes contact information (corporate email, phone, address) that is publicly published on corporate websites, in order to improve cyber-risk visibility of organizations in Türkiye.",
      },
      {
        heading: "Data Processed",
        body: "Publicly available corporate contact information, domain name, city, and sector.",
      },
      {
        heading: "Purpose",
        body: "Cyber-risk analysis, preparation of aggregate reports such as the \"Türkiye Cyber Risk Index,\" and corporate security assessment.",
      },
      {
        heading: "Legal Basis",
        body: "The legitimate interest of the data controller under Article 5/2-(f) of Turkish Data Protection Law No. 6698 (KVKK), provided that the fundamental rights and freedoms of the data subject are not harmed. Your data is processed on this basis without requiring your explicit consent.",
      },
      {
        heading: "Your Rights",
        body: "Under Article 11 of KVKK, you have the right to learn whether your personal data is being processed, to object to such processing, and to request its erasure. Upon your objection, your personal contact data (email, phone, address) will be removed from our systems; non-personal information such as domain name, city, and sector may be retained in anonymized form.",
      },
      {
        heading: "Requests",
        body: "Please send your requests to kvkk@cyberstep.io. Your request will be resolved as soon as possible and within the statutory timeframes.",
      },
    ],
  },
};

const SECTIONS = [
  {
    icon: Database,
    title: "1. Veri Sorumlusunun Kimliği",
    content: `6698 sayılı Kişisel Verilerin Korunması Kanunu ("KVKK") kapsamında veri sorumlusu sıfatıyla CyberStep.io ("Platform") hareket etmektedir.\n\nPlatform; siber güvenlik risk değerlendirmesi hizmeti sunmak amacıyla kişisel verileri aşağıda açıklanan kapsamda işlemektedir.`,
  },
  {
    icon: Eye,
    title: "2. İşlenen Kişisel Veriler",
    content: `Platform aracılığıyla aşağıdaki kategorilerde kişisel veriler işlenmektedir:\n\n• Kimlik verileri: Ad, soyad, firma adı, unvan\n• İletişim verileri: E-posta adresi, telefon numarası\n• Değerlendirme verileri: Risk anketi cevapları, sektör bilgisi, çalışan sayısı, değerlendirme raporları\n• Teknik veriler: IP adresi, tarayıcı tipi, oturum verileri, çerezler\n• Finansal veriler: Ödeme işlem kaydı (kart bilgileri Platform tarafından işlenmez; ödeme altyapısı üçüncü taraf sağlayıcı üzerinden çalışır)\n• Alan adı güvenlik tarama verileri: DNS kayıtları, SSL durumu, e-posta güvenlik yapılandırması (yalnızca tarama talep edilmesi halinde)`,
  },
  {
    icon: UserCheck,
    title: "3. Veri İşleme Amaçları ve Hukuki Dayanaklar",
    content: `Kişisel verileriniz aşağıdaki amaçlar ve yasal dayanaklara göre işlenmektedir:\n\n• Sözleşmenin ifası (KVKK m.5/2-c): Siber güvenlik değerlendirmesi hizmetinin sunulması, kişiselleştirilmiş raporların oluşturulması, müşteri hesabının yönetimi\n• Meşru menfaat (KVKK m.5/2-f): Platform güvenliğinin sağlanması, hizmet kalitesinin iyileştirilmesi, istatistiksel analizler, dolandırıcılığın önlenmesi\n• Yasal yükümlülük (KVKK m.5/2-ç): Vergi, muhasebe ve yasal kayıt gereksinimleri\n• Açık rıza (KVKK m.5/1): Pazarlama amaçlı iletişim, ticari elektronik ileti gönderimi`,
  },
  {
    icon: Lock,
    title: "4. Veri Güvenliği Tedbirleri",
    content: `Kişisel verilerinizin güvenliğini sağlamak için aşağıdaki teknik ve idari tedbirler uygulanmaktadır:\n\n• TLS/SSL şifrelemesi ile tüm veri iletişimi güvence altına alınmaktadır\n• Hassas veriler (şifreler) tek yönlü kriptografik özet (hash) ile saklanmaktadır\n• Rol tabanlı erişim kontrolü uygulanmakta; verilere yalnızca yetkili personel erişebilmektedir\n• Düzenli güvenlik denetimleri ve log izleme süreçleri yürütülmektedir\n• Veri ihlali tespiti halinde KVKK m.12 kapsamında 72 saat içinde Kişisel Verileri Koruma Kurulu'na bildirim yapılmaktadır\n• İlgili kişilere gecikme olmaksızın bildirim gerçekleştirilmektedir`,
  },
  {
    icon: Database,
    title: "5. Kişisel Verilerin Aktarılması",
    content: `Kişisel verileriniz aşağıdaki taraflara, belirtilen amaçlar doğrultusunda aktarılabilir:\n\n• Yapay zeka hizmet sağlayıcıları: Rapor analizinin oluşturulması amacıyla anonim veya pseudonim veri aktarımı\n• E-posta altyapı sağlayıcıları: Rapor bildirimi ve bilgilendirme e-postalarının iletilmesi\n• Ödeme hizmet sağlayıcıları: Ücretli hizmet işlemleri için ödeme bilgilerinin aktarımı\n• Hukuki, mali veya düzenleyici otoriteler: Yasal yükümlülük kapsamında zorunlu durumlarda\n\nKişisel verileriniz açık rızanız olmaksızın üçüncü taraflarla ticari amaçla paylaşılmaz veya satılmaz.`,
  },
  {
    icon: Database,
    title: "6. Kişisel Verilerin Saklanma Süreleri",
    content: `• Değerlendirme ve rapor verileri: Hizmet ilişkisinin sona ermesinden itibaren 3 yıl\n• Müşteri hesap bilgileri: Hesap silme talebinden itibaren 30 gün içinde imha\n• Finansal işlem kayıtları: Vergi mevzuatı gereği 10 yıl\n• Teknik log kayıtları: 90 gün\n• Pazarlama rızası geri alındığında: Derhal pazarlama listesinden çıkarma\n\nSaklama süresi dolan veriler periyodik imha takvimi kapsamında silinmekte, yok edilmekte veya anonim hale getirilmektedir.`,
  },
  {
    icon: UserCheck,
    title: "7. İlgili Kişi Hakları (KVKK m.11)",
    content: `KVKK'nın 11. maddesi kapsamında aşağıdaki haklara sahipsiniz:\n\n• Kişisel verilerinizin işlenip işlenmediğini öğrenme\n• İşlenen verileriniz hakkında bilgi talep etme\n• Kişisel verilerinizin işlenme amacını ve bunların amacına uygun kullanılıp kullanılmadığını öğrenme\n• Yurt içinde veya yurt dışında aktarıldığı üçüncü kişileri bilme\n• Kişisel verilerinizin eksik veya yanlış işlenmiş olması halinde düzeltilmesini isteme\n• KVKK m.7 kapsamında kişisel verilerinizin silinmesini veya yok edilmesini isteme\n• Otomatik sistemler vasıtasıyla aleyhinize sonuç doğuran kararlara itiraz etme\n• Hukuka aykırı işleme nedeniyle zarara uğramanız halinde zararın giderilmesini talep etme`,
  },
  {
    icon: Mail,
    title: "8. Başvuru Yöntemi",
    content: `Haklarınızı kullanmak için aşağıdaki yollardan başvurabilirsiniz:\n\n• E-posta: info@cyberstep.io (güvenli elektronik imza veya kayıtlı elektronik posta ile)\n• Platform içi: Hesabım sayfasından yazılı talep formu\n• Posta: Şirket adresine ıslak imzalı yazılı başvuru\n\nBaşvurular KVKK m.13 gereğince en geç 30 gün içinde ücretsiz olarak yanıtlanacaktır. Talebin aşırı maliyet gerektirmesi halinde Kişisel Verileri Koruma Kurulu tarafından belirlenen tarifeye göre ücret alınabilir.`,
  },
  {
    icon: Trash2,
    title: "9. Çerez Politikası",
    content: `Platform; oturum yönetimi, güvenlik ve kullanıcı deneyimini iyileştirme amacıyla çerezler kullanmaktadır.\n\n• Zorunlu çerezler: Platformun teknik işlevselliği için gereklidir, rıza aranmaz\n• İşlevsel çerezler: Dil tercihi gibi kişiselleştirme ayarları için kullanılır\n• Analitik çerezler: Anonim platform kullanım istatistikleri için, açık rıza ile\n\nTarayıcı ayarlarınızdan çerezleri devre dışı bırakabilirsiniz. Zorunlu çerezlerin engellenmesi platform işlevselliğini olumsuz etkileyebilir.\n\nDetaylı bilgi için Çerez Politikamızı inceleyiniz.`,
  },
  {
    icon: Lock,
    title: "10. Politika Güncellemeleri",
    content: `Bu Aydınlatma Metni, yasal değişiklikler, platform güncellemeleri veya veri işleme süreçlerindeki değişiklikler nedeniyle güncellenebilir. Önemli değişiklikler e-posta yoluyla veya platform üzerinden ilgili kişilere bildirilecektir. Güncel metne her zaman bu sayfadan ulaşabilirsiniz.`,
  },
];

export default function Kvkk() {
  const { lang } = useLanguage();
  const { data: settings } = useQuery<Record<string, string>>({
    queryKey: ["public-settings"],
    queryFn: () => fetch("/api/public/settings").then(r => r.json()),
    staleTime: 60000,
  });

  const kvkkContent = settings?.["kvkk.content"];
  const notice = lang === "en" ? WEB_SCRAPING_NOTICE.en : WEB_SCRAPING_NOTICE.tr;

  return (
    <div className="min-h-screen bg-background">

      {/* Header */}
      <div className="bg-slate-900 text-white py-16">
        <div className="container mx-auto px-4 max-w-4xl text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <FileText className="h-10 w-10 text-emerald-400" />
            <h1 className="text-4xl font-bold">{lang === "en" ? "KVKK Disclosure Text" : "KVKK Aydınlatma Metni"}</h1>
          </div>
          <p className="text-slate-400">6698 Sayılı Kişisel Verilerin Korunması Kanunu kapsamında hazırlanmıştır</p>
        </div>
      </div>

      {/* Content */}
      <div className="container mx-auto px-4 max-w-4xl py-12">

        {/* ── Kamuya Açık Veri İşleme Aydınlatma Metni ─────────────────── */}
        <div className="bg-card border-2 border-emerald-200 dark:border-emerald-900 rounded-2xl overflow-hidden mb-10">
          {/* Başlık */}
          <div className="flex items-center gap-3 px-6 py-4 bg-emerald-50 dark:bg-emerald-950/40 border-b border-emerald-200 dark:border-emerald-900">
            <Globe className="h-5 w-5 text-emerald-600 shrink-0" />
            <span className="text-xs font-semibold uppercase tracking-widest text-emerald-700 dark:text-emerald-400">
              {notice.badge}
            </span>
          </div>
          <div className="px-6 py-6 space-y-5">
            <h2 className="text-base font-bold tracking-wide text-foreground">
              {notice.title}
            </h2>
            {/* Veri Sorumlusu satırı */}
            <div className="flex items-center gap-3 py-2 px-3 rounded-lg bg-muted/50 text-sm">
              <Shield className="h-4 w-4 text-emerald-600 shrink-0" />
              <span className="font-medium text-muted-foreground">{notice.controller.label}:</span>
              <span className="font-semibold text-foreground">{notice.controller.value}</span>
            </div>
            {/* Madde satırları */}
            {notice.rows.map(({ heading, body }) => (
              <div key={heading}>
                <div className="text-xs font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 mb-1">
                  {heading}
                </div>
                <p className="text-sm text-muted-foreground leading-relaxed">{body}</p>
              </div>
            ))}
            {/* E-posta bağlantısı */}
            <div className="pt-2 border-t border-border">
              <a
                href="mailto:kvkk@cyberstep.io"
                className="inline-flex items-center gap-2 text-sm font-medium text-emerald-600 hover:text-emerald-700 transition-colors"
              >
                <Mail className="h-4 w-4" />
                kvkk@cyberstep.io
              </a>
            </div>
          </div>
        </div>

        {kvkkContent && (
          <div className="bg-card border rounded-2xl p-6 mb-8 prose prose-slate dark:prose-invert max-w-none">
            <pre className="whitespace-pre-wrap font-sans text-sm text-foreground leading-relaxed">{kvkkContent}</pre>
          </div>
        )}

        {/* Veri Sorumlusu Kartı */}
        <div className="bg-card border rounded-2xl p-6 mb-8 flex items-center gap-4">
          <div className="h-12 w-12 rounded-full bg-emerald-50 dark:bg-emerald-900/20 flex items-center justify-center shrink-0">
            <Shield className="h-6 w-6 text-emerald-600" />
          </div>
          <div>
            <div className="font-semibold text-base">Veri Sorumlusu</div>
            <div className="text-muted-foreground text-sm mt-0.5">CyberStep.io — info@cyberstep.io</div>
          </div>
          <div className="ml-auto text-xs text-muted-foreground text-right">
            <div>Son güncelleme</div>
            <div className="font-medium text-foreground">
              {new Date().toLocaleDateString("tr-TR", { day: "2-digit", month: "long", year: "numeric" })}
            </div>
          </div>
        </div>

        {/* İçerik Bölümleri */}
        <div className="space-y-4">
          {SECTIONS.map(({ icon: Icon, title, content }) => (
            <div key={title} className="bg-card border rounded-xl overflow-hidden">
              <div className="flex items-center gap-3 px-6 py-4 border-b bg-muted/30">
                <Icon className="h-4 w-4 text-emerald-600 shrink-0" />
                <h2 className="font-semibold text-sm">{title}</h2>
              </div>
              <div className="px-6 py-5">
                <p className="text-sm text-muted-foreground leading-relaxed whitespace-pre-line">{content}</p>
              </div>
            </div>
          ))}
        </div>

        {/* İlgili Sayfalar */}
        <div className="mt-10 grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { label: "Gizlilik Politikası", href: "/gizlilik-politikasi" },
            { label: "Çerez Politikası", href: "/cerez-politikasi" },
            { label: "Kullanım Koşulları", href: "/kullanim-kosullari" },
          ].map(({ label, href }) => (
            <Link
              key={href}
              href={href}
              className="flex items-center justify-between px-4 py-3 bg-card border rounded-lg text-sm font-medium hover:bg-muted/50 transition-colors"
            >
              {label}
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
