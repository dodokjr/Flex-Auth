import { App, Router, adapters, cors, createAuth, createAuthRouter } from '../src';
import { JWT_Access, JWT_Refresh } from '../AuthPage/Jwt';
import { getGoogleSheetsConfig } from '../AuthPage/GoogleSheets';


// 1) Pilih storage
const adapter = process.env.STORAGE === 'sheets'
  ? adapters.googleSheetsAdapter(getGoogleSheetsConfig())
  : adapters.memoryAdapter();

// 2) Buat instance auth
const auth = createAuth({
  adapter,
  jwt: {
    accessSecret: JWT_Access,
    refreshSecret: JWT_Refresh,
    accessExpiresIn: '15m',
    refreshExpiresIn: '7d',
  },
  otp: {
    enabled: true,
    requireOnLogin: false,
    // Tanpa sender kustom: library hanya menampilkan OTP di development dan
    // menolak mengirim OTP di production sampai provider email/WA/SMS dikonfigurasi.
  },
});

// 3) Rakit aplikasi
const app = new App({ trustProxy: false });
app.use(cors({ origins: ['http://localhost:5173'] })); // sesuaikan origin frontend Anda
app.use('/auth', createAuthRouter(auth, {
  dashboard: async (user) => ({ message: `Halo ${user.name ?? user.email}`, role: user.role }),
}));

// Contoh route sendiri yang diproteksi
const admin = new Router();
admin.get('/', auth.authenticate(), auth.authorize('admin'), (ctx) => {
  ctx.json(200, { ok: true, who: ctx.state.auth });
});
app.use('/admin-only', admin);

const port = Number(process.env.PORT ?? 3000);
app.listen(port).then(() =>
  console.log(`Server jalan di http://localhost:${port} (storage: ${process.env.STORAGE ?? 'memory'})`));
