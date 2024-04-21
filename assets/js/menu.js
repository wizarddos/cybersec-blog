const menuButton = document.querySelector("#open-menu")

const main = document.querySelector('.main')
const sidenav = document.querySelector('.sidenav')

const toogleClasses = () =>{
    sidenav.classList.toggle("hidden")
    main.classList.toggle("darken")
}

menuButton.addEventListener("click", toogleClasses)