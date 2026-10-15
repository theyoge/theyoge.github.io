(function () {
  var btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.addEventListener('click', function () {
      var root = document.documentElement;
      var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    });
  }
})();

(function () {
  var bar = document.querySelector('.filter-bar');
  if (!bar) return;

  var chips = Array.prototype.slice.call(bar.querySelectorAll('.filter-chip'));
  var posts = Array.prototype.slice.call(document.querySelectorAll('.post-item'));

  bar.addEventListener('click', function (e) {
    var chip = e.target.closest('.filter-chip');
    if (!chip) return;

    chips.forEach(function (c) {
      c.classList.toggle('is-active', c === chip);
    });

    var filter = chip.getAttribute('data-filter');
    posts.forEach(function (post) {
      var cats = (post.getAttribute('data-categories') || '').trim().split(/\s+/);
      var show = filter === 'all' || cats.indexOf(filter) !== -1;
      post.style.display = show ? '' : 'none';
    });
  });
})();
