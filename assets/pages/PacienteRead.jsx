import React, {useState, useEffect, Component} from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import Swal from 'sweetalert2/dist/sweetalert2.js';
import axios from 'axios';

function PacienteRead(){ //esse componente é responsável pela página inicial, onde todos os pacientes são exibidos
    const [pacienteList, setPacienteList] = useState([])
    const [pacienteSearch, setPacienteSearch] = useState([])
    const [lista, setLista] = useState([]);

    //quando o componente é renderizado, ou seus states são alterados
    useEffect(() => {
        fetchPacienteList()
    }, [])

    const fetchPacienteList = () => { //essa função é responsável por retornar a lista de pacientes retornada pela api e armazená-la nos states adequados
        axios.get('/api/').then(function (response) { //chama a api via get
            setPacienteList(response.data); //seta o state PacienteList
            setLista(response.data) //seta o state lista (necessário por haver a possibilidade de filtrar pacientes)
        }).catch(function (error) {
            Swal.fire({icon: 'error', title: 'Não foi possível carregar os pacientes'});
        })
    }

    const handleDelete = (id) => { //é executado quando o usuário clica no botão de deletar algum paciente
        Swal.fire({ //alert do tipo confirm solicitando se o usuário realmente quer deletar o paciente
            title: 'Você tem certeza que quer excluir o registro desse paciente?',
            text: "Não será possível reverter!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#dd2606',
            cancelButtonColor: 'blue',
            confirmButtonText: 'Sim, excluir esse paciente!'
        }).then((result) => {
            if(result.isConfirmed){ //se o usuário confirmar a exclusão
                axios.delete('/api/delete/'+id).then(function (response) { //chama a api via get mandando apenas o id do paciente a ser deletado
                    Swal.fire({
                        icon: 'success',
                        title: 'Paciente deletado com sucesso!',
                        showConfirmButton: false,
                        timer: 1500
                    })
                    fetchPacienteList()
                }).catch(function (error){
                    Swal.fire({
                        icon: 'error',
                        title: 'Ocorreu um erro interno!',
                        showConfirmButton: false,
                        timer: 1500
                    })
                })
            }
        })
    }

    const handleChangeStatus = (id) => { //é executado quando o usuário clica em alterar o status de um paciente
        axios.post('/api/changeStatus/'+id).then(function (response){ //o estado é alterado via api get passando o id do paciente
            document.location.reload(true);
        }).catch(function (error){
            Swal.fire({
                icon: 'error',
                title: 'Ocorreu um erro interno!',
                showConfirmButton: false,
                timer: 1500
            })
        })
    }

    const handleSearch = () => { //é executado quando o usuário pressiona o botão de pesquisar pelo nome do paciente
        const formData = new FormData();
        formData.append('input', document.getElementById('search').value);
        axios.post('/api/searchName/', formData).then(response => {
            setLista(response.data);
        }).catch(() => Swal.fire({icon: 'error', title: 'Não foi possível pesquisar'}));
    }

    return ( //retorna o componente
        <Layout>
            <div className="container-fluid">
                <h2 className="text-center mt-5 mb-3 text-light">Pacientes ACME</h2>
                <div className="card">
                    <div className="row p-2 d-flex justify-content-start headerSearch">
                        <Link className='col-2 mx-3 btn btn-outline-primary' to="/create">Cadastrar Paciente</Link>
                        <div className="col-8">
                            <form className="form-inline my-2 my-lg-0 row">
                                <div className="col-6"><input id='search' className="form-control mr-sm-2" type="search" placeholder="Pesquise pelo nome do paciente..." aria-label="Pesquisar" /></div>
                                <div className="col-6"><button onClick={(event) => {event.preventDefault(); handleSearch();}} className="btn btn-outline-success my-2 my-sm-0">Pesquisar</button></div>
                            </form>
                        </div>
                    </div>
                    <div className="card-body">
                        <table className="table table-responsive table-bordered table-light table-hover">
                            <thead>
                                <tr>
                                <th scope="col">Nome</th>
                                <th scope="col">Data Nascimento</th>
                                <th scope="col">CPF</th>
                                <th scope="col">Sexo</th>
                                <th scope="col">Endereço</th>
                                <th scope="col">Status</th>
                                <th scope="col" width="240px">Ação</th>
                                </tr>
                            </thead>
                            <tbody id="tbody">
                                {
                                    lista.map((paciente, key) => { {/* mapeia todo o state lista considerando cada paciente */}
                                        return(
                                            <tr key={key}>
                                                <td>{paciente.nome}</td>
                                                <td>{paciente.dataNasc ? paciente.dataNasc: paciente.data_nascimento}</td>
                                                <td>{paciente.cpf}</td>
                                                <td>{paciente.sexo}</td>
                                                <td>{paciente.endereco}</td>
                                                <td>
                                                    <span className='mx-1'>{paciente.status ? "Ativo" : "Inativo"}</span>
                                                    <button onClick={() => handleChangeStatus(paciente.id)} className="btn btn-outline-primary mx-1">
                                                        Alterar
                                                    </button>
                                                </td>
                                                <td>
                                                    <Link to={'/edit/'+paciente.id} className="btn btn-outline-success mx-1">
                                                        Editar
                                                    </Link>
                                                    <button onClick={() => handleDelete(paciente.id)} className="btn btn-outline-danger mx-1">
                                                        Deletar
                                                    </button>
                                                </td>
                                            </tr>
                                        )
                                    })
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </Layout>
    )
}

export default PacienteRead; //exporta o componente PacienteRead