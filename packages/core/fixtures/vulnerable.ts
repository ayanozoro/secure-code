import express from 'express';

const router = express.Router();

router.get('/users/:id', async (req, res) => {
  // scanner-ignore: this one is intentionally ignored for suppression validation
  const ignoredUser = await db.findOne(`select * from users where id = ${req.params.id}`);
  const user = await db.findOne(`select * from users where id = ${req.params.id}`);
  res.json({ ignoredUser, user });
});

router.post('/search', async (req, res) => {
  const filter = req.body.filter;
  const rows = await db.query(`select * from orders where status = '${filter}'`);
  res.json(rows);
});

export default router;
