// Mobile navigation toggle
(function () {
  var burger = document.getElementById('burger');
  var links = document.getElementById('nav-links');
  if (!burger || !links) return;

  function setOpen(open) {
    burger.setAttribute('aria-expanded', String(open));
    burger.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    links.classList.toggle('is-open', open);
    if (open) {
      links.style.setProperty('visibility', 'visible', 'important');
      links.style.setProperty('opacity', '1', 'important');
      links.style.setProperty('transform', 'none', 'important');
      links.style.setProperty('transition', 'none', 'important');
    } else {
      links.style.setProperty('visibility', 'hidden', 'important');
      links.style.setProperty('opacity', '0', 'important');
      links.style.setProperty('transform', 'translateY(-8px)', 'important');
      links.style.removeProperty('transition');
    }
  }

  burger.addEventListener('click', function () {
    setOpen(burger.getAttribute('aria-expanded') !== 'true');
  });

  links.addEventListener('click', function (e) {
    if (e.target.closest('a')) setOpen(false);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') setOpen(false);
  });

  window.addEventListener('resize', function () {
    if (window.innerWidth > 820) setOpen(false);
  });
})();

// Hero image slider
(function () {
  var slides = Array.from(document.querySelectorAll('.hero__slide'));
  var dots = Array.from(document.querySelectorAll('.hero__dot'));
  var previous = document.getElementById('hero-prev');
  var next = document.getElementById('hero-next');
  if (!slides.length || slides.length !== dots.length || !previous || !next) return;

  var activeIndex = 0;

  function showSlide(index) {
    activeIndex = (index + slides.length) % slides.length;
    slides.forEach(function (slide, i) {
      var isActive = i === activeIndex;
      slide.classList.toggle('is-active', isActive);
      slide.setAttribute('aria-hidden', String(!isActive));
    });
    dots.forEach(function (dot, i) {
      var isActive = i === activeIndex;
      dot.classList.toggle('is-active', isActive);
      dot.setAttribute('aria-current', String(isActive));
    });
  }

  previous.addEventListener('click', function () {
    showSlide(activeIndex - 1);
  });
  next.addEventListener('click', function () {
    showSlide(activeIndex + 1);
  });
  dots.forEach(function (dot, i) {
    dot.addEventListener('click', function () {
      showSlide(i);
    });
  });

  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    window.setInterval(function () {
      showSlide(activeIndex + 1);
    }, 4000);
  }
})();

// Testimonials: arrows scroll the card track (NEW)
(function () {
  var track = document.getElementById('reviews-track');
  var prev = document.getElementById('reviews-prev');
  var next = document.getElementById('reviews-next');
  if (!track || !prev || !next) return;

  function step(dir) {
    var card = track.querySelector('.review');
    if (!card) return;
    var gap = parseFloat(getComputedStyle(track).columnGap) || 0;
    track.scrollBy({ left: dir * (card.getBoundingClientRect().width + gap), behavior: 'smooth' });
  }

  prev.addEventListener('click', function () { step(-1); });
  next.addEventListener('click', function () { step(1); });
})();

// Hero shipment tracking form
(function () {
  var form = document.getElementById('tracking-form');
  var input = document.getElementById('tracking-code');
  var status = document.getElementById('tracking-status');
  if (!form || !input || !status) return;

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var code = input.value.trim();
    if (!code) {
      status.textContent = 'Please enter a tracking code.';
      input.focus();
      return;
    }
    status.textContent = 'Tracking "' + code + '". Shipment details will appear here.';
  });
})();