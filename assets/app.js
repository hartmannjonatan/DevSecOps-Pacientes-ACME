/* Esse arquivo contém toda a importação de js (e jsx) utilizado, é o js principal */

// any CSS you import will output into a single css file (app.css in this case)
import './styles/app.css';
import 'bootstrap/dist/css/bootstrap.min.css';
// Build the dialog CSS as an asset instead of injecting an inline style under CSP.
import 'sweetalert2/dist/sweetalert2.min.css';

import 'bootstrap/dist/js/bootstrap.bundle'


// start the Stimulus application
import './bootstrap';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import PacienteRead from './pages/PacienteRead'
import PacienteCreate from './pages/PacienteCreate'
import PacienteEdit from './pages/PacienteEdit';

//a const main é responsável por renderizar os componentes corretos de acordo com a rota acessada pelo usuário
const main = (
    <Router>
        <Routes>
            <Route exact path='/' element={<PacienteRead/>} /> {/* Renderiza a página inicial */}
            <Route path='/create' element={<PacienteCreate/>} /> {/* Renderiza o formulário de cadastro */}
            <Route path='/edit/:id' element={<PacienteEdit/>} /> {/* Renderiza o formulário de atualização */}
        </Routes>
    </Router>
)

createRoot(document.getElementById('app')).render(main); //renderiza o componente main dentro da div "app" do html padrão

